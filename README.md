milter-ns
=========

A Milter to block Email based on the sending domain's Name Server
Copyright (c) 2014, Montagar Software, Inc.

As I've been getting more SPAM lately, I was trying to figure out a way to
stop more of it.  Looking at the domains, they were all using "Privacy Protection"
and often registered via Moniker.  Then Moniker seemed to get tired of them and they
moved to ENOM as a Registrar.  Often the domains where registered the same day of
the spam.

The common item was they were always using ENOM as the Name Server for the
domain.  So if the only mail I'm getting from ENOM registered domain is SPAM,
I can just write a milter to get the HELO/EHLO and MAILFROM information, check
the Name Server for that domain, and fail the transaction if it's using their
name servers.

It seems pretty effective, as SPAM that gets by the RBL's has dropped considerably.

Licensing
----------

See COPYING  for license information.

Prerequisites
--------------

        sendmail

Installation
------------

        ./configure --prefix=/usr

        Add a similar line to /etc/mail/sendmail.mc:
        INPUT_MAIL_FILTER(`mymilter', `S=unix:/var/run/milter-ns.sock, T=S:30s;R:30s;E:5m')

        Rebuild sendmail.cf, and restart:
        make
        systemctl restart sendmail

        Add the folling file to /etc/init:

        milter-ns.conf

        This file will insure the milter is started before sendmail is started


