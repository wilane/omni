import re
import time
import requests
import json
from AnimusExceptions import *


class AnimusAuthLog:

    ################################
    # Description:
    #   Constructor for the AnimusAuthLog object. Pass it a fileName and it will handle
    #   reduction for Auth events.
    #
    # Params:
    #   logfile - The array of log lines to be reduced
    #   apiKey - The api key pulled from the ~/.animus.cfg file
    #   baseUri - The base URI of the animus API, as stored in the ~/.animus.cfg file
    #   year - The year we should assume the log file is from
    ################################

    def __init__(self, logfile, apiKey, baseUri, year=2017):
        self.BASE_URI = baseUri
        self.API_ENDPOINT = '/va/auth'
        self.apiKey = apiKey
        self.year = year
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

        # Go through every parsed log line
        i = 0

        oldParsedLog = list(parsedLog)

        while i < len(parsedLog):

            # This line is going to have some features we need to extract
            lineFeatures = {}

            # If we are an auth log, we can do something
            if parsedLog[i]['service'] == 'sshd':

                # Get ip's and usernames
                lineFeatures = self._parseAuthMessage(parsedLog[i])

                # Compare the IP address in the log to see if it's in the filter
                if 'ip' in lineFeatures:
                    for filterItem in self.filter:



                        # TODO: Right now we are just checking the ip address and timestamp
                        # TODO: We should check and see if there is a match on a successful login so we can make it important. Need to change parse function for this
                        if lineFeatures['ip'] == filterItem['ip'] and parsedLog[i]['datetime'] <= filterItem['endtime'] and parsedLog[i]['datetime'] >= filterItem['starttime']:
                            # We are at a log line that matches our filter
                            
                            # Lets save the pid and remove all entries with this pid
                            delPid = parsedLog[i]['pid']

                            # Search for the same pid within 20 lines and eliminate
                            for x in range(-10, 10):
                                # Current position plus offset, x + i
                                # If we have a log with the pid we want to delete

                                # Check to make sure it's in bounds
                                if i+x < 0 or i+x > len(parsedLog):
                                    continue

                                if parsedLog[x+i]['pid'] == delPid:
                                    # Pop the log from the list and add it to the list of noisy logs
                                    self.noisyLogs.append((parsedLog.pop(x+i)))

                                    # Backup the current index to account for the missing item
                                    i -= 10
            i += 1

        # The quiet logs are everything that's left
        self.quietLogs = parsedLog

        self.parsedLog = oldParsedLog

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
            parsedLine = self._parseLine(line)
            self.parsedLog.append(parsedLine)

            if 'service' in parsedLine and 'datetime' in parsedLine:

                # If we are an auth log, we need to extract more metadata
                if parsedLine['service'] == 'sshd':

                    result = self._parseAuthMessage(parsedLine)

                    # Save to our global list of features

                    if 'ip' in result and 'datetime' in parsedLine:

                        # If our IP doesn't have an entry, make one
                        if result['ip'] not in features:
                            features[result['ip']] = {}
                            features[result['ip']]['ip'] = result['ip']
                            features[result['ip']]['starttime'] = parsedLine['datetime']
                            features[result['ip']]['endtime'] = parsedLine['datetime']
                            features[result['ip']]['usernames'] = []

                        # See if we have a username in this log line
                        if 'username' in result:
                            
                            # Add our username to the list if it isnt there already
                            if result['username'] not in features[result['ip']]['usernames']:
                                features[result['ip']]['usernames'].append(result['username'])

                        # See if this log is earlier than the previous earliest log. If so, set it
                        if features[result['ip']]['starttime'] > parsedLine['datetime']:
                            features[result['ip']]['starttime'] = parsedLine['datetime']

                        # See if this log is later than the previous latest log. If so, set it
                        if features[result['ip']]['endtime'] < parsedLine['datetime']:
                            features[result['ip']]['endtime'] = parsedLine['datetime']

                # If we are not an auth log, we are not handling it right now
                else:
                    pass

            else:
                # If we can't parse this, toss an exception. We will probably try as something else.
                raise AnimusLogParsingException('auth')

        #returnedFeatures = []
        #
        #for ip in features:
        #    returnedFeatures.append(features[ip])
        #
        #return returnedFeatures

        for ip in features:
            self.features.append(features[ip])


    ################################
    # Description:
    #   Parse an auth message to see if we have ip addresses or users that we care about
    #
    # Params:
    #   parsedLine - The auth message we are trying to parse
    #
    # Returns:
    #   response - A dict object that contains metadata for the auth message
    ################################

    def _parseAuthMessage(self, parsedLine):

        # TODO: We should save if it was a success or failure so we can make a bad ip with a successful login highly important

        # These are the regexes for auth messages that we can accurately extract from
        REGEXES_INVALID_USER = [
            "^Invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            "^error: maximum authentication attempts exceeded for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2 \[preauth\]$",
            "^error: maximum authentication attempts exceeded for invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2 \[preauth\]$",
            "^Failed password for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2$",
            "^pam_unix\(sshd:auth\): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(?P<user>\w+)$",
            "^PAM \d+ more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(?P<user>\w+)$",
            "^message repeated \d+ times: \[ Failed password for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2\]$",
            "^Failed password for invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2$"

        ]

        REGEXES_INVALID_IP = [
            "^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: (Bye Bye|ok)?(\s)?\[preauth\]$",
            #"^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: Bye Bye \[preauth\]$",
            #"^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: ok \[preauth\]$",
            "^Connection closed by (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[preauth\]$",
            "^reverse mapping checking getaddrinfo for [\w|\.|-]+ \[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] failed - POSSIBLE BREAK-IN ATTEMPT!$",
            "^Did not receive identification string from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            "^Disconnected from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]$",
            "^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+:11: \[preauth\]$",
            "^Connection closed by (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]$",
            "^pam_unix\(sshd:auth\): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        ]

        REGEXES_IGNORE = [
            "^input_userauth_request: invalid user \w+ \[preauth\]$",
            "^Disconnecting: Too many authentication failures for \w+ \[preauth\]$",
            "^fatal: Read from socket failed: Connection reset by peer \[preauth\]$",
            "^Accepted publickey for \w+ from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} port \d+ ssh2: RSA (\w\w:){15}\w\w$",
            "^pam_unix(sshd:session): session opened for user \w+ by (uid=\d+)$",
            "^Received disconnect from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}: 11: disconnected by user$",
            "^pam_unix\(sshd:session\): session closed for user \w+(\s by \s)?(\(uid=\d+\))?$",
            "^pam_unix\(sshd:session\): session opened for user \w+ by \(uid=\d+\)$",
            "^pam_unix\(sshd:auth\): check pass; user unknown$"
        ]

        result = {}

        authMessage = parsedLine['message']

        hasMatched = False

        for REGEX in REGEXES_INVALID_USER:
            # Check for the invalid user/ip messages
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Save the username and IP
                result['username'] = m.group('user')
                result['ip'] = m.group('ip')

        for REGEX in REGEXES_INVALID_IP:
            # Check for the invalid ip messages
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Save the  IP
                result['ip'] = m.group('ip')                        

        for REGEX in REGEXES_IGNORE:
            # Check for messages we want to ignore
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Do nothing
                pass

        # If it's an ssh log and we don't know what it is, handle that
        if not hasMatched:
            self._unhandledAuthLog(parsedLine)

        return result


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
            # TODO: Not sure if this is a good idea in the general case for log files
            splitLine = logLine.split()
            
            # Get the timestamp, assuming the year that was passed to us
            response['datetime'] = int(time.mktime(time.strptime(" ".join(splitLine[0:3]) + " " + str(self.year), "%b %d %H:%M:%S %Y")))

            # We have to make sure it isn't in the future though. If it is, subtract a year.
            # TODO: There's a better way to do this
            if response['datetime'] > int(time.time()):
                response['datetime'] = response['datetime'] - 31536000 

            # Get the service name
            process = splitLine[4]

            splitProc = re.split('\W+', process)
            response['service'] = splitProc[0]

            # Get the PID
            response['pid'] = splitProc[1]

            # Get the log message
            response['message'] = " ".join(splitLine[5:])

            # Save the raw message
            response['raw'] = logLine   

        except Exception as e:
            # TODO: Handle the error better
            #print(e)
            pass

        return response

    ################################
    # Description:
    #   If we have an auth log that we don't have a regex for, we need to add it to a list of unhandled log lines
    #
    # Params:
    #   parsedLine - The parsed auth log line that we don't know how to handle 
    #
    ################################

    def _unhandledAuthLog(self, parsedLine):
        self.unhandledLogs.append(parsedLine['message'])


    ################################
    # Description:
    #   Send a query to the backend api with a list of observed features in this log file
    #
    # Params:
    #   features - The list of features we want to query
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
            raise AnimusAPIUnavailable("Request failed and returned a status of: " + str(r.status_code))

        return json.loads(r.text)




