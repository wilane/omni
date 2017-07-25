import re
import requests
import json
from AnimusExceptions import *


class AnimusGenericLog:

    ################################
    # Description:
    #   Initializer for the AnimusGenericLog object. Pass it a fileName and it will handle
    #   reduction for generic logs.
    #
    # Params:
    #   logfile - The array of lines in the logfile we are analyzing
    #   port - The port and protocol list to obtain a filter for
    #   apiKey - The api key pulled from the ~/.animus.cfg file
    #   baseUri - The base URI of the animus API, as stored in the ~/.animus.cfg file
    ################################

    def __init__(self, logfile, ports, apiKey, baseUri):
        self.BASE_URI = baseUri
        self.API_ENDPOINT = '/va/generic'
        self.apiKey = apiKey
        self.unhandledLogs = []
        self.features = {}
        self.features['ips'] = []
        self.features['ports'] = []
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

        # Add port and protocol
        for port in ports:
            portsItem = {}
            (portsItem['port'], portsItem['protocol']) = port.split(':')
            self.features['ports'].append(portsItem)

        #Set the filter for the file
        self._getFilter()

        # self.filter is now set


        # Perform the analysis operation
        self._analyze()

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

    def _analyze(self, ):
        # Go through each line
        for line in self.parsedLog:
            if 'ip' in line:
                if line['ip'] in self.filter['ips']:
                    self.noisyLogs.append(line)
                    continue
                else:
                    self.quietLogs.append(line)
            else:
                self.quietLogs.append(line)


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
    #   logfile - The array of log lines to be analyzed
    #
    # Returns:
    #   Nothing. Sets self.parsedLog, self.features, and self.unhandledLogs
    ################################

    def _getFeatures(self, logfile):

        REGEX_GET_IP = '(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

        # The dict that holds the features of the log file
        features = {}

        #print(type(logfile))
        #print(len(logfile))
        for line in logfile:

            # Clear previous results
            result = {}

            # Save the raw line
            result['raw'] = line

            # Search for an IP in the line
            m = re.search(REGEX_GET_IP, line)

            # If we found one, save it
            if m:
                result['ip'] = m.group('ip')
                if result['ip'] not in self.features['ips']:
                    self.features['ips'].append(result['ip'])

            self.parsedLog.append(result)


    ################################
    # Description:
    #   Send a query to the backend api with a list of observed features in this log file
    #
    # Params:
    #   features - The list of features we want to return a filter for
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





