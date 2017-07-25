Animus Omni CLI Quickstart Guide 
================================

.. image:: https://img.shields.io/gitter/room/nwjs/nw.js.svg
    :target: https://gitter.im/Animus-Intelligence/Animus.io

The Animus Omni CLI helps you separate the signal from the noise in your logfiles. If you are running a service that faces the internet, you likely see thousands of scans, bots, and brute force attempts every day. These scans clog up your log files, and make it hard to find legitimate events of interest.

The Animus Omni CLI is a utility that leverages the Animus API to reduce noisy entries from your log files. This tool is currently in ALPHA and will be available for free with rate-limited accounts.

How it Works
------------

Animus Omni is powered by a network of sensors that are deployed across the internet. These sensors have no business value, but have a comprehensive set of logging rules. These logs are aggregated and analyzed before being loaded into a database that is made available through the Animus API. omni-reduce analyzes your log files, and passes metadata to our API. The API returns a filter based on your metadata that is then applied to your file. The result is less noisy log files.

Installation
------------

From the source repository::


    $ python setup.py install

Or via PyPi::

    $ pip install animus-omni

Configuration
-------------

This command will ask you to provide your e-mail address, which will register a rate limited account for you to use for free during the alpha period::

    $ omni-reduce --configure

Usage
-----

Commandline usage for the omni-reduce tool::

    usage: omni-reduce [-h] [--type {auth,http,generic}] [--noise]
                       [--out-file OUTFILE] [--stats] [--dry-run] [--port PORTS]
                       [--configure]
                       [filename]

    positional arguments:
      filename              Filename of log file to reduce

    optional arguments:
      -h, --help            show this help message and exit
      --type {auth,http,generic}, -t {auth,http,generic}
                            Log type to analyze
      --noise, -n           Print the noise from the file rather than reducing it
      --out-file OUTFILE, -o OUTFILE
                            Output file for the result
      --stats, -s           Print statistics to STDERR from the reduction
                            operation
      --dry-run, -d         Don't output the reduced log file, only print possible
                            reduction statistics to STDERR
      --port PORTS, -p PORTS
                            Port and protocol used by generic mode. Can be used
                            multiple times. Should be of the form "80:TCP" or
                            "53:UDP"
      --configure           Configure Omni Reduce.

Examples
--------

Output a reduced auth log to the screen::

    $ omni-reduce /var/log/auth.log
    [Results not shown]


Output a reduced auth log to a file and print aggregate statistics to the screen::

    $ omni-reduce --output ~/auth.log.reduced -s /var/log/auth.log
    489 lines were analyzed in this log file.
    356 lines were determined to be noise by Animus.
    133 lines were not determined to be noise by Animus.
    The input file was reduced to 27.2% of it's original size.


Output a reduced HTTP access log to a file::

    $ omni-reduce -t http --output ~/access.log.reduced /etc/log/access.log


Output lines from an HTTP access log that Animus believes to be bots, crawlers, or other internet noise::

    $ cat /etc/log/access.log | omni-reduce -t http -n
    [Results not shown]

Show statistics for reducing an access log by traffic seen by Animus on TCP port 80, and do not display results to the screen::

    $ omni-reduce -t generic -p 80:tcp --dry-run test/data/access.log.txt

Privacy Notice
--------------
In order to reduce noise from your log files, we need to collect metadata from those file. This includes IP addresses, usernames, user agent strings, referrers, and request URI's. We use this metadata to enchance the results of our API. If you have sensitive data in your log files or prefer to not share this data with us, contact us at info@animus.io about a private on-premesis solution.

