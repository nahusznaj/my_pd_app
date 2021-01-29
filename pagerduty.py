from flask import Flask, request, make_response
import requests
import json
import pprint
import time 
import hmac 
import hashlib
import urllib.parse 

from dotenv import load_dotenv
load_dotenv()

import os
PD_token = os.getenv("PD_token")
slack_signing_secret = os.getenv("slack_signing_secret")

app = Flask(__name__)

# poll PD to obtain a list with all the schedules.
payload_schedules =  {'total':'true', 'limit':100}
schedules_id = []

rr = requests.get('https://api.pagerduty.com/schedules', headers = {"Authorization":'Token token='+PD_token},  params = payload_schedules)

schedules_page_response = json.loads(rr.text)

all_schedules_list = schedules_page_response['schedules']

for i,j in enumerate(all_schedules_list):
    schedules_id.append(j['id'])

def signature_verification(timestamp, slack_payload_dict, signign_secret, incoming_slack_signature):
    incoming_payload = "&".join(['='.join([key, urllib.parse.quote(val, safe='')]) for key, val in slack_payload_dict.items()]) # we're parsing the payload to replace characters / -> %2, : -> %3A

    ### compose the message for our side's sha256 signature
    sig_basestring = 'v0:' + timestamp + ':' + incoming_payload
    sig_basestring = sig_basestring.encode('utf-8')

    ### Signing Secret provided by Slack upon creating the App, encoded:
    signing_secret = slack_signing_secret.encode('utf-8')
    
    ## create our signature
    my_signature = 'v0=' + hmac.new(signing_secret, sig_basestring, hashlib.sha256).hexdigest()

    if my_signature == incoming_slack_signature:  
        return True
    else:
        return False

def user_text_input_verification(input_text):
    return input_text == ''

def obtain_oncalls_results(schedules_list):
    ## read the schedules for each scheduleID item 
    payload = {'time_zone':'America/Argentina/Buenos_Aires', 'total':'true', 'schedule_ids[]':schedules_list, 'limit':100} #scheduleIDs 
    r = requests.get('https://api.pagerduty.com/oncalls', headers = {"Authorization":'Token token='+PD_token},  params = payload)
    
    pager_response = json.loads(r.text)
    
    ## create a dict with each schedule and the oncall user
    information_dict = {}
    for i,j in enumerate(pager_response['oncalls']):
        if j['schedule']['summary'] not in information_dict:
            information_dict[j['schedule']['summary']] = j['user']['summary']

    information_dict = dict( sorted(information_dict.items(), key=lambda x: x[0].lower()) )

    output = '\n'.join("{}: {}".format(k, v) for k, v in information_dict.items()) # produce the text message for the response

    return output 

@app.route('/', methods=['POST']) 
def all_schedules():

    slack_headers = request.headers

    slack_signature = slack_headers['X-Slack-Signature'] # this is the signature that Slack sends along the POST, in the headers.
    timestamp = slack_headers['X-Slack-Request-Timestamp'] #absolute time in headers sent by Slack

        ### Security measure ###
        # The request timestamp is more than five minutes from local time.
        # It could be a replay attack, so let's ignore it. Otherwise, the controller continues
    if timestamp is not None:
        timestamp = float(timestamp)
        if abs(time.time() - timestamp) > 60 * 5:
            return '', 403  

    timestamp2 = slack_headers['X-Slack-Request-Timestamp'] # another var of absolute time in headers sent by Slack
    
    slack_payload = request.form
    
    # this is the payload in the body of the request from Slack to our app when the slash command was executed in Slack
    dict_slack = slack_payload.to_dict() 

    ### Security measure ###
    # verify the signature, if successful this will be True
    signature_validation_result = signature_verification(timestamp2, dict_slack, slack_signing_secret, slack_signature) 
    
    ### Security measure ###
    user_text_input = dict_slack['text']  # declare the incoming request's text input (hoping it'll be empty!)
    input_text_verif_result = user_text_input_verification(user_text_input) # verify no input text was passed, if successful this will be True
    
    # if the signatures match and no text was passed, let's then run this show!
    if signature_validation_result and input_text_verif_result: 
        output = obtain_oncalls_results(schedules_id)
        response = make_response(output, 200)
        response.mimetype = "text/plain"
        return response
    elif signature_validation_result and not input_text_verif_result: 
        response = make_response('Error: Text input is not permitted', 200)
        response.mimetype = "text/plain"
        return response
    elif not signature_validation_result: 
        response = make_response('', 403)
        response.mimetype = "text/plain"
        return response

if __name__ == "__main__":
    app.run(debug=True)