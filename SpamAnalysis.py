import json
import sqlite3
import re
from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file as oauth_file, client, tools

WILDCARD_DOMAIN = 'pollen.cc'

email_re = re.compile(r'([a-zA-Z0-9_\-.]+@[a-zA-Z0-9_\-.]+)')

def get_client():
    store = oauth_file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
        creds = tools.run_flow(flow, store)
    client = build('gmail', 'v1', http=creds.authorize(Http()))
    return client

def list_spambox(msgclient=None, req=None, res=None):
    if not msgclient:
        msgclient = get_client().users().messages()
    if not req:
        req = msgclient.list(userId="me", labelIds="SPAM")
    else:
        req = msgclient.list_next(req, res)
    for res in req.execute()['messages']:
        yield res

def get_db_conn():
    conn = sqlite3.connect('messages.sqlite')
    conn.execute('CREATE TABLE IF NOT EXISTS messages (id int primry key, from_domain text, to_addr text, pollen_trap text, full_json json, unique(id));')
    return conn

def db_store(msg_id, from_domain, to_addr, pollen_trap, content, conn=None):
    conn = conn if conn else get_db_conn()
    conn.execute("insert or ignore into messages values (?,?,?,?,?)", (msg_id, from_domain, to_addr, pollen_trap, content))

def clean_email(email):
    m = email_re.search(email)
    return m.group() if m else email

def process_message(msgdetails):
    headers = msgdetails['payload']['headers']
    from_domain = None
    possible_to = set()
    for h in headers:
        if h['name'] in ('Delivered-To', 'To'):
            addr = clean_email(h['value'])
            if addr:
                possible_to.add(addr)
        elif h['name'] == 'From':
            from_addr = clean_email(h['value'])
            from_domain = from_addr.split('@')[1] if from_addr else None
    
    to_addr = None
    pollen_trap = None
    for addr in possible_to:
        if addr.endswith("@" + WILDCARD_DOMAIN):
            pollen_trap = addr.split('@')[0]
            to_addr = addr
            break
        elif not to_addr:
            to_addr = addr
    content = json.dumps(msgdetails, indent=2)
    return (msgdetails['id'], from_domain, to_addr, pollen_trap, content)

def main():
    client = get_client()
    msgclient = client.users().messages()
    conn = get_db_conn()
    for msg in list_spambox(msgclient):
        print "Got: {}".format(msg)
        msgdetails = msgclient.get(userId='me', id=msg['id']).execute()
        props = process_message(msgdetails)
        db_store(*props, conn=conn)
    conn.commit()
    
if __name__ == "__main__":
    main()