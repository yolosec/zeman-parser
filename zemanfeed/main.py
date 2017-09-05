#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gc
import logging
import os
import pprint
import resource
import sys
import threading
import time
import traceback
from threading import Lock as Lock

import argparse
import coloredlogs
import mem_top
import queue
import sqlalchemy as salch
import tweepy
from blessed import Terminal
from cmd2 import Cmd

import databaseutils
import util
from __init__ import CONFIG_DIR
from config import Config
from core import Core
from daemon import Daemon
from database import Base as DB_Base
from database import DbDonations

__author__ = 'yolosec'
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class AppDeamon(Daemon):
    def __init__(self, *args, **kwargs):
        Daemon.__init__(self, *args, **kwargs)
        self.app = kwargs.get('app')
        print(self.app)

    def run(self):
        self.app.work()


class App(Cmd):
    """
    Zeman feeder and parser bot
    """
    prompt = '$> '

    def __init__(self, *args, **kwargs):
        Cmd.__init__(self, *args, **kwargs)
        self.core = Core()
        self.t = Terminal()

        self.last_result = None
        self.args = None
        self.noninteractive = None
        self.config = None

        self.logdir = '.'
        self.piddir = '.'

        self.daemon = None
        self.running = True
        self.run_thread = None
        self.stop_event = threading.Event()
        self.local_data = threading.local()

        self.follow_queue = queue.PriorityQueue()
        self.follow_queue_set = set()
        self.follow_queue_lock = Lock()
        self.crawl_thread = None

        self.publish_thread = None
        self.monitor_dir = None

        self.db_config = None
        self.engine = None
        self.session = None

        self.api = None
        self.auth = None

    def return_code(self, code=0):
        self.last_result = code
        return code

    def is_dry_run(self):
        return self.args.dryrun

    def start_daemon(self):
        self.daemon = AppDeamon(os.path.join(CONFIG_DIR, 'zeman.pid'),
                                stderr=os.path.join(self.logdir, "stderr.log"),
                                stdout=os.path.join(self.logdir, "stdout.log"),
                                app=self)
        self.daemon.start()

    def init_db(self):
        """
        Initializes database engine & session.
        Has to be done on main thread.
        :return:
        """
        self.db_config = databaseutils.process_db_config(self.config.get_config('db'))

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker, scoped_session
        self.engine = create_engine(self.db_config.constr, pool_recycle=3600)
        self.session = scoped_session(sessionmaker(bind=self.engine))

        # Make sure tables are created
        DB_Base.metadata.create_all(self.engine)

    #
    # CLI
    #

    def do_quit(self, arg):
        self.running = False
        self.stop_event.set()
        logger.info('Waiting for thread termination')

        Core.write_configuration(self.config)

        time.sleep(1)
        logger.info('Quitting')
        return Cmd.do_quit(self, arg)

    do_q = do_quit
    do_exit = do_quit

    def do_status(self, arg):
        """Prints the current queue status"""
        try:
            self.try_status(arg)
        except Exception as e:
            traceback.print_exc()
            logger.error('Exception: %s' % e)

    def try_status(self, arg):
        """Prints the current queue status"""

    def do_limits(self, arg):
        """Queries for latest rate limits
        https://dev.twitter.com/rest/reference/get/application/rate_limit_status
        :param arg:
        :return:
        """
        self.twitter_login_if_needed()
        resources = arg if arg is not None and len(arg) > 0 else None
        res = self.api.rate_limit_status(resources=resources)
        pprint.pprint(res)

    def do_reset(self, line):
        print('\033c')

    def do_gc(self, line):
        gc.collect()

    def do_mem_top(self, line):
        print(mem_top.mem_top())

    def do_mem(self, line):
        print('Memory usage: %s kB' % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

    #
    # Twitter auth
    #

    def twitter_login(self):
        """
        Twiter auth
        :return:
        """
        self.auth = tweepy.OAuthHandler(self.config.consumer_key, self.config.consumer_secret)
        self.auth.set_access_token(self.config.access_key, self.config.access_secret)
        self.api = tweepy.API(self.auth)

    def twitter_login_if_needed(self):
        """
        Create twitter instances if needed
        :return:
        """
        if self.api is None:
            self.twitter_login()

    #
    # Work
    #

    def work(self):
        """
        Main work method for Twitter.search(), started either in the daemon or in the separate thread.
        :return:
        """
        logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            self.twitter_login_if_needed()

            while not self.stop_event.is_set():
                self.interruptible_sleep(10)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception: %s' % e)
            logger.error(e)

        logger.info('Work loop terminated')

    def crawl_main(self):
        """
        Main worker method for the crawling
        :return:
        """
        logger.info('Crawl thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            while not self.stop_event.is_set():
                s = None
                try:
                    self.interruptible_sleep(10)  # crawl each 10 seconds

                    s = self.session()
                    self.crawl_cycle(s)

                except Exception as e:
                    traceback.print_exc()
                    logger.error('Exception in crawling nest: %s', e)

                finally:
                    util.silent_close(s)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in crawling: %s' % e)

        finally:
            pass

        logger.info('Crawl loop terminated')

    def crawl_cycle(self, s):
        """
        Crawling cycle
        :param s:
        :return:
        """
        # TODO: add
        # TODO: crawl page, add new donations to the database (not added before).

        # Template to add to DB
        entity = DbDonations()
        entity.created_at = salch.func.now()
        entity.received_at = util.try_parse_datetime_string('05.09.2017')
        entity.message = 'test'
        entity.amount = 0.1
        # s.add(entity)
        # s.commit()

    #
    # Publish
    #

    def publish_main(self):
        """
        Main thread for monitoring internal state & dumping it to a file.
        Important also for storing the whole state and resume after the restart.
        :return:
        """
        logger.info('Publish thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            while not self.stop_event.is_set():
                s = None
                try:
                    self.interruptible_sleep(2)

                    s = self.session()
                    self.publish_cycle(s)

                except Exception as e:
                    traceback.print_exc()
                    logger.error('Exception in publishing: %s', e)

                finally:
                    util.silent_close(s)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in publishing: %s' % e)

        finally:
            pass

        logger.info('Publish loop terminated')

    def publish_cycle(self, s):
        """
        Publish new stuff
        :param s: session
        :return:
        """
        q = s.query(DbDonations)\
            .filter(DbDonations.published_at == None)\
            .order_by(DbDonations.received_at, DbDonations.created_at)
        q = databaseutils.DbHelper.yield_limit(q, DbDonations.id, 100)

        for donation in q:  # type: DbDonations
            try:
                # sleep before page load. If there is an exception or empty page we sleep
                # to avoid hitting usage limits.
                self.interruptible_sleep(5)

                message = self.donation_to_msg(donation)
                if self.args.dryrun:
                    logger.info('Publishing: %s' % message)
                    continue

                donation.publish_attempts += 1
                donation.publish_last_attempt_at = salch.func.now()

                self.api.update_status(message)

                donation.published_at = salch.func.now()
                s.commit()

                if self.args.test:
                    self.interruptible_sleep(60)

            except tweepy.RateLimitError as rle:
                logger.warning('Rate limit hit, sleep a while. %s' % rle)
                self.interruptible_sleep(5*60)

            except Exception as ex:
                logger.error('Exception in API publish: %s' % ex)
                raise

    def donation_to_msg(self, donation):
        """
        Converts donation to the message
        :param donation:
        :return:
        """
        to_del = ['MGR.', 's.r.o.', 'Ing.', 'a.s.', 'PhD.']

        tmp = donation.donor.upper()
        for s in to_del:
            tmp = tmp.replace(s.upper(), "")

        initials = ""
        for x in tmp.split():
            initials += x[0]

        money = "{}Kč".format(donation.amount).replace('.', ',')
        msg = "{}({}):{}".format(initials, money, donation.message)
        return util.smart_truncate(msg)

    #
    # Management, CLI, API, utils
    #

    def interruptible_sleep(self, sleep_time):
        """
        Sleeps the current thread for given amount of seconds, stop event terminates the sleep - to exit the thread.
        :param sleep_time:
        :return:
        """
        if sleep_time is None:
            return

        sleep_time = float(sleep_time)

        if sleep_time == 0:
            return

        sleep_start = time.time()
        while not self.stop_event.is_set():
            time.sleep(0.1)
            if time.time() - sleep_start >= sleep_time:
                return

    def work_loop(self):
        self.config = Core.read_configuration()
        if self.config is None or not self.config.has_nonempty_config():
            sys.stderr.write('Configuration is empty: %s\nCreating default one... (fill in access credentials)\n'
                             % Core.get_config_file_path())

            Core.write_configuration(Config.default_config())
            return self.return_code(1)

        # DB init
        self.init_db()

        # Kick off twitter - for initial load
        self.twitter_login_if_needed()

        # Sub threads
        self.crawl_thread = threading.Thread(target=self.crawl_main, args=())
        self.crawl_thread.start()

        self.publish_thread = threading.Thread(target=self.publish_main, args=())
        self.publish_thread.start()

        # Daemon vs. run mode.
        if self.args.daemon:
            self.start_daemon()

        elif self.args.direct:
            self.work()

        else:
            # start thread with work method.
            self.run_thread = threading.Thread(target=self.work, args=())
            self.run_thread.start()

            # work locally
            logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
            self.cmdloop()

    def app_main(self):
        # Backup original arguments for later parsing
        args_src = sys.argv

        # Parse our argument list
        parser = argparse.ArgumentParser(description='Milos parser and feeder')
        parser.add_argument('-n', '--non-interactive', dest='noninteractive', action='store_const', const=True,
                            help='non-interactive mode of operation, command line only')
        parser.add_argument('-l','--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')
        parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                            help='enables debug mode')
        parser.add_argument('--test', dest='test', action='store_const', const=True,
                            help='enables test mode')

        parser.add_argument('-s', '--sleep', dest='sleep', default=30*60,
                            help='timeout sleep between scanning rounds in seconds')

        parser.add_argument('-f', '--dry', dest='dryrun', action='store_const', const=True, default=False,
                            help='dry run (no twitter action taken)')

        parser.add_argument('-d', '--daemon', dest='daemon', default=False, action='store_const', const=True,
                            help='Runs in daemon mode, no CLI')

        parser.add_argument('--direct', dest='direct', default=False, action='store_const', const=True,
                            help='Runs in direct mode = on master thread, no CLI')

        parser.add_argument('commands', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='commands to process')

        self.args = parser.parse_args(args=args_src[1:])
        self.noninteractive = self.args.noninteractive

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        # Fixing cmd2 arg parsing, call cmdLoop
        sys.argv = [args_src[0]]
        for cmd in self.args.commands:
            sys.argv.append(cmd)

        # Terminate after execution is over on the non-interactive mode
        if self.noninteractive:
            sys.argv.append('quit')

        self.work_loop()
        sys.argv = args_src
        pass


app = None


def main(app):
    app.app_main()


if __name__ == '__main__':
    # Global object, reachable by python interpreter
    app = App()
    main(app)

