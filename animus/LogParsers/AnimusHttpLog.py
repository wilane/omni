import re
import time, datetime, pytz
import requests
import json
import sys
from AnimusExceptions import *


class AnimusHttpLog:

    ################################
    # Description:
    #   Initializer for the AnimusHttpLog object. Pass it a fileName and it will handle
    #   reduction for http access logs.
    #
    # Params:
    #   logfile - The array of lines in the logfile we are analyzing
    #   apiKey - The api key pulled from the ~/.animus.cfg file
    #   baseUri - The base URI of the animus API, as stored in the ~/.animus.cfg file
    ################################

    def __init__(self, logfile, apiKey, baseUri):
        self.BASE_URI = baseUri
        self.API_ENDPOINT = '/va/http'
        self.apiKey = apiKey
        self.unhandledLogs = []
        self.features = []
        self.parsedLog = []
        self.filter = []

        # quietLogs are logs that have had noise removed
        self.quietLogs = []

        # noisyLogs are logs that we think are noise
        self.noisyLogs = []

        # alertLogs are logs where we think a noisy actor managed to do something bad
        # For example, if someone has a successful auth attempt, but they
        # are known to be brute forcing ssh servers, they may have successfully broken in
        self.alertLogs = []


        # Get the features from the file
        self._getFeatures(logfile)

        # These variables are now set:
        # self.unhandledLogs
        # self.features
        # self.parsedLog


        #Set the filter for the file
        self._getFilter()

        # self.filter is now set


        # Perform the analysis operation
        self._analyze(self.parsedLog)

        # self.noisyLogs and self.quietLogs is now set


    ################################
    # Description:
    #   Print the reduced log file
    #
    # Params
    #   showQuietLogs - If this is true, shows the reduced log file. If this is false, it shows the logs that were deleted.
    #
    ################################

    def reduce(self, showNoisy=False):
        if not showNoisy:
            for log in self.quietLogs:
                yield log['raw'].strip()
        else:
            for log in self.noisyLogs:
                yield log['raw'].strip()


    ################################
    # Description:
    #   Apply the filter to the log file
    #
    ################################

    def _analyze(self, parsedLog):

        # Go through every line
        for line in self.parsedLog:

            # This is our flag if we need to filter the item
            filterMe = False
            for filterItem in self.filter:

                # If the source of this line is in our filter, don't print it
                # TODO: This needs to be smarter
                if 'source' in line and line['source'] == filterItem['ip']:
                    filterMe = True
                    break

            if not filterMe:
                self.quietLogs.append(line)
            else:
                self.noisyLogs.append(line)

    ################################
    # Description:
    #   Gets the filter for the features in the object
    ################################

    def _getFilter(self, ):
        self.filter = self._sendAuthFeatureQuery(self.features)


    ################################
    # Description:
    #   Get the feature data from the log file necessary for a reduction
    # 
    # Params:
    #   logfile - The file to extract features from
    #
    # Returns:
    #   Nothing. Sets self.parsedLog, self.features, and self.unhandledLogs
    ################################

    def _getFeatures(self, logfile):

        # The dict that holds the features of the log file
        features = {}

        for line in logfile:

            # Clear previous results
            result = {}

            # Parse the line to extract metadata
            # Save it to a parsed log object
            try:
                parsedLine = self._parseLine(line)
                self.parsedLog.append(parsedLine)

            except AnimusLogParsingException:
                result['raw'] = line
                self.parsedLog.append(result)

            if 'datetime' in parsedLine:

                # If we have no record of the IP, lets make it
                if parsedLine['source'] not in features:
                    features[parsedLine['source']] = {}
                    features[parsedLine['source']]['ip'] = parsedLine['source']
                    features[parsedLine['source']]['starttime'] = parsedLine['datetime']
                    features[parsedLine['source']]['endtime'] = parsedLine['datetime']
                    features[parsedLine['source']]['paths'] = []
                    features[parsedLine['source']]['referers'] = []
                    features[parsedLine['source']]['useragents'] = []


                # See if we have a path in this log line
                if 'path' in parsedLine:
                    
                    # Add our path to the list if it isnt there already
                    if parsedLine['path'] not in features[parsedLine['source']]['paths']:
                        features[parsedLine['source']]['paths'].append(parsedLine['path'])


                # See if we have a referer in this log line
                if 'referer' in parsedLine:
                    
                    # Add our referer to the list if it isnt there already
                    if parsedLine['referer'] not in features[parsedLine['source']]['referers']:
                        features[parsedLine['source']]['referers'].append(parsedLine['referer'])


                # See if we have a username in this log line
                if 'useragent' in parsedLine:
                    
                    # Add our username to the list if it isnt there already
                    if parsedLine['useragent'] not in features[parsedLine['source']]['useragents']:
                        features[parsedLine['source']]['useragents'].append(parsedLine['useragent'])


                # See if this log is earlier than the previous earliest log. If so, set it
                if features[parsedLine['source']]['starttime'] > parsedLine['datetime']:
                    features[parsedLine['source']]['starttime'] = parsedLine['datetime']

                # See if this log is later than the previous latest log. If so, set it
                if features[parsedLine['source']]['endtime'] < parsedLine['datetime']:
                    features[parsedLine['source']]['endtime'] = parsedLine['datetime']

            else:
                # If we can't parse this, we need to toss an exception
                raise AnimusLogParsingException('http')

        # Set the features
        for ip in features:
            self.features.append(features[ip])


    ################################
    # Description:
    #   Parse the individual log line and return structured metadata we care about
    #
    # Params:
    #   logLine - The individual line we are trying to parse
    #
    # Returns:
    #   response - A dict object that contains metadata for the log line. Returns the PID, service name, and timestamp
    ################################

    def _parseLine(self, logLine):
        response = {}

        try:
            # Split on spaces
            splitLine = logLine.split()
            
            # TODO: The source can possibly be DNS, so we need to figure out what to do with that
            response['raw'] = logLine
            response['source'] = splitLine[0]
            response['user-identifier'] = splitLine[1]
            response['userid'] = splitLine[2]

            splitLine = " ".join(splitLine[3:])

            # TODO: If somebody has a custom log format, this part is totally going to fail
            # If they have an apache config file, we could likely build the regex from it
            # https://httpd.apache.org/docs/1.3/logs.html
            # LogFormat "%h %l %u %t \"%r\" %>s %b" common
            # This basically gives us everything we need to know

            # Here we are matching and seeing if there are extra fields at the end, which would indicate combined rather than common log format
            m = re.search("^\[(?P<timestamp>.+)?\]\s\"(?P<request>.+?)\"\s(?P<responseCode>\d+)\s(?P<size>\d+)(?P<combinedFields>.*)", splitLine)

            # Set the fields we know
            # TODO: Better timestamp handling. This is a disaster. Who invented time, anyway?
            t = m.group('timestamp')

            # We cant handle the timezone offset, so lets separate it
            lastSpace = t.rindex(' ')

            # Lets make a timestamp for everything that isnt the timezone
            # CHECKME We maybe should do this whole timestamp thing a little better
            tmptime = int(time.mktime(time.strptime(t[:lastSpace], "%d/%b/%Y:%H:%M:%S")))

            # Pull the timezone in the form of -0400, 0000, +0500, ..., etc.
            tzs = t[lastSpace+1:]

            # Parse the freaking timezone offset
            sign = 1
            if tzs.startswith("-"):
                sign = -1
                tzs = tzs[1:]
            elif tzs.startswith("+"):
                tzs = tzs[1:]

            # Convert to minutes and apply +/-
            minutes = int(tzs[0:2])*60 + int(tzs[2:4])
            minutes *= sign

            # Adjust by the number of seconds
            tmptime += minutes*60

            # Save what we know
            response['datetime'] = tmptime
            response['request'] = m.group('request')
            response['responseCode'] = m.group('responseCode')
            response['size'] = m.group('size')

            # If we have combined log fields, let's parse them
            if m.group('combinedFields') is not "":
                n = re.search("^\s\"(?P<referer>.+)\"\s\"(?P<useragent>.+)\"", m.group('combinedFields'))

                # Make sure it isn't empty
                if n.group('referer') != '-':
                    response['referer'] = n.group('referer')

                if n.group('useragent') != '-':
                    response['useragent'] = n.group('useragent')

            # Lets pull the request apart if we can
            # TODO: We should validate this, but we can guess for now
            # This will 100% fail on malformed requests
            # If it's a well formed request, there will be a method, a URI, and an HTTP version
            response['method'] = response['request'].split()[0]
            response['httpversion'] = response['request'].split()[-1]
            response['path'] = " ".join(response['request'].split()[1:-1])

            return response

        except Exception as e:

            # If we cant parse it, toss an exception
            raise AnimusLogParsingException('http')

        return response


    ################################
    # Description:
    #   If we have an http log that we don't have a regex for, we need to add it to a list of unhandled log lines
    #
    # Params:
    #   parsedLine - The un-parsed http log line that we don't know how to handle 
    #
    ################################

    def _unhandledHttpLog(self, parsedLine):
        self.unhandledLogs.append(parsedLine)


    ################################
    # Description:
    #   Send a query to the backend api with a list of observed features in this log file
    #
    # Params:
    #   features - The parsed auth log line that we don't know how to handle 
    #
    # Returns:
    #   logFilter - A list of features that should be filtered out of the log file
    ################################

    def _sendAuthFeatureQuery(self, features):
        
        try:
            r = requests.post(self.BASE_URI + self.API_ENDPOINT, data = json.dumps(features), headers={'api_key': self.apiKey})
        except requests.exceptions.ConnectionError as e:
            raise AnimusAPIUnavailable("The Animus API appears to be unavailable.")


        if r.status_code != 200:
            raise AnimusAPIUnavailable("Request failed and returned a status of: {STATUS}".format(STATUS=r.status_code))

        return json.loads(r.text)




