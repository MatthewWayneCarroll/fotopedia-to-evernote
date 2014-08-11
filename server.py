from flask import Flask, session, redirect, url_for, request, render_template
from BeautifulSoup import BeautifulSoup as bs
import requests
import re

import urlparse
import urllib
import thrift.protocol.TBinaryProtocol as TBinaryProtocol
import thrift.transport.THttpClient as THttpClient
import evernote.edam.userstore.UserStore as UserStore
import evernote.edam.notestore.NoteStore as NoteStore
import oauth2 as oauth

import evernote.edam.type.ttypes as Types
import evernote.edam.notestore.ttypes as NoteStoreTypes
from evernote.edam.notestore.ttypes import NotesMetadataResultSpec
import evernote.edam.error.ttypes as en_errors
import binascii
import hashlib



EN_CONSUMER_KEY = 'enter your consumer key here'
EN_CONSUMER_SECRET = 'enter your consumer secret here'
EN_REQUEST_TOKEN_URL = 'https://www.evernote.com/oauth'
EN_ACCESS_TOKEN_URL = 'https://www.evernote.com/oauth'
EN_AUTHORIZE_URL = 'http://www.evernote.com/OAuth.action'
EN_HOST = "www.evernote.com"
EN_USERSTORE_URIBASE = "https://" + EN_HOST + "/edam/user"
EN_NOTESTORE_URIBASE = "https://" + EN_HOST + "/edam/note/"
APP_SECRET_KEY = 'enter app secret key here (for cookies/session varibles)'
EN_URL="https://www.evernote.com"

app=Flask(__name__)
app.config['SECRET_KEY'] = APP_SECRET_KEY

def get_oauth_client(token=None):
    """Return an instance of the OAuth client."""
    consumer = oauth.Consumer(EN_CONSUMER_KEY, EN_CONSUMER_SECRET)
    if token:
        client = oauth.Client(consumer, token)
    else:
        client = oauth.Client(consumer)
    return client


def get_notestore():
    """Return an instance of the Evernote NoteStore. Assumes that 'shardId' is
    stored in the current session."""
    shardId = session['shardId']
    noteStoreUri = EN_NOTESTORE_URIBASE + shardId
    noteStoreHttpClient = THttpClient.THttpClient(noteStoreUri)
    noteStoreProtocol = TBinaryProtocol.TBinaryProtocol(noteStoreHttpClient)
    noteStore = NoteStore.Client(noteStoreProtocol)
    return noteStore


def get_userstore():
    """Return an instance of the Evernote UserStore."""
    userStoreHttpClient = THttpClient.THttpClient(EN_USERSTORE_URIBASE)
    userStoreProtocol = TBinaryProtocol.TBinaryProtocol(userStoreHttpClient)
    userStore = UserStore.Client(userStoreProtocol)
    return userStore


def get_published_stories_ids(username, password):
	try:
		payload={'username_or_email':username,'password':password,'callback':'Picor.LoginFormCallBack','final_host':'www.fotopedia.com','target_application':'reporter'}

		s=requests.Session()

		s.post('https://login.fotopedia.com/apps/login/do_login',data=payload)
		
		published_response=s.get('http://www.fotopedia.com/apps/reporter/me/published/query?filter=published&offset=0&limit=10')
		published_json=published_response.json()
		note_list=[]
		for item in published_json['items']:
			note_list.append(item['_id'])

		return note_list
	except:
		return None


def get_draft_stories_ids(username, password):
	try:
		payload={'username_or_email':username,'password':password,'callback':'Picor.LoginFormCallBack','final_host':'www.fotopedia.com','target_application':'reporter'}

		s=requests.Session()

		s.post('https://login.fotopedia.com/apps/login/do_login',data=payload)
		
		published_response=s.get('http://www.fotopedia.com/apps/reporter/me/drafts/query?filter=draft&offset=0&limit=10')
		published_json=published_response.json()
		note_list=[]
		for item in published_json['items']:
			note_list.append(item['_id'])

		return note_list
	except:
		return None

def sync_fotopedia_id(item_id):
	#get html story page
	raw_story=requests.get("http://www.fotopedia.com/reporter/stories/"+item_id) 

	#pass html story to beautiful soup for html processing
	bs_story=bs(raw_story.content) 

	#grab all titles and captions
	editable_spans=bs_story.findAll("span",{'class':"editable-value"})
	titles_and_captions=[]
	for text in editable_spans:
		titles_and_captions.append(text.text)

	#grab all pic urls from page
	re_pattern="\'background: url\(\"(.*)\"\)"
	pic_html=bs_story.findAll("div",{"class":"full-image"})
	pic_urls=[]
	for pic in pic_html:
		pic_urls.append(re.findall(re_pattern,pic.renderContents())[0])

	#prep evernote
	user_store = get_userstore()
	note_store = get_notestore()
	notebooks = note_store.listNotebooks(session['identifier'])
	
	#check if Fotopedia notebook exists
	for notebook in notebooks:
		if notebook.name=="Fotopedia":
			fotopediaNotebookGuid=notebook.guid
			break
	#if not create it
	try: 
		fotopediaNotebookGuid
	except NameError:
		notebook=Types.Notebook()
		notebook.name="Fotopedia"
		notebook=note_store.createNotebook(session['identifier'], notebook)
		fotopediaNotebookGuid=notebook.guid

	#add all pictures as notes with title of story: title of pic with captions as body text
	#iterate through all pics and titles
	for iter in range(len(pic_urls)):
		if titles_and_captions[0] and titles_and_captions[2*iter]:
			note_title=titles_and_captions[0]+" - "+titles_and_captions[2*iter]
		else:
			note_title=titles_and_captions[2*iter]

		note_description=titles_and_captions[2*iter-1]
		pic_url=pic_urls[iter]

		#check to see if note exists already
		notebook_filter=NoteStoreTypes.NoteFilter()
		notebook_filter.guid=fotopediaNotebookGuid
		result_spec = NotesMetadataResultSpec(includeTitle=True)
		noteList    = note_store.findNotesMetadata(session['identifier'], notebook_filter,0 , 40000, result_spec)

		for note in noteList.notes:
			if note.title==note_title:
				continue
		
		#get image
		if pic_url == '':
			continue
		image= requests.get(pic_url, stream=True).content
		md5 = hashlib.md5()
		md5.update(image)
		pic_hash = md5.digest()

		data = Types.Data()
		data.size = len(image)
		data.bodyHash = pic_hash
		data.body = image

		resource = Types.Resource()
		resource.mime = 'image/jpeg'
		resource.data = data

		hash_hex = binascii.hexlify(pic_hash)

		
		note = Types.Note()
		note.notebookGuid=fotopediaNotebookGuid #create note for our Giphy notebook
		
		note.title=note_title 
		note.content = '<?xml version="1.0" encoding="UTF-8"?>'
		note.content += '<!DOCTYPE en-note SYSTEM ' \
		    '"http://xml.evernote.com/pub/enml2.dtd">'
		note.content += '<en-note>'+note_description+'<br/><br/>'
		note.content += '<en-media type="image/png" hash="' + hash_hex + '"/>'
		note.content += '</en-note>'
		
		note.resources = [resource] # Now, add the new Resource to the note's list of resources


		note=note_store.createNote(session['identifier'], note) # create the note


	return True
	

@app.route('/')
def start():
	return render_template('index.html')

@app.route('/en_error')
def en_error():
	return render_template('en_error.html')

@app.route('/auth')
def auth_start():
    """Makes a request to Evernote for the request token then redirects the
    user to Evernote to authorize the application using the request token.

    After authorizing, the user will be redirected back to auth_finish()."""
    
    try:
        
        client = get_oauth_client()
        
        # Make the request for the temporary credentials (Request Token)
        callback_url = 'http://www.fotopediatoevernote.com/authComplete'
        request_url = '%s?oauth_callback=%s' % (EN_REQUEST_TOKEN_URL, callback_url)
   
        resp, content = client.request(request_url, 'GET')
    
        if resp['status'] != '200':

            return render_template("en_error.html")
	
        request_token = dict(urlparse.parse_qsl(content))

        # Save the request token information for later
        session['oauth_token'] = request_token['oauth_token']
        session['oauth_token_secret'] = request_token['oauth_token_secret']
       
        # Redirect the user to the Evernote authorization URL
        return redirect('%s?oauth_token=%s' % (EN_AUTHORIZE_URL, urllib.quote(session['oauth_token'])))
        
    except Exception as err:
        return err


@app.route('/authComplete')
def auth_finish():
    """After the user has authorized this application on Evernote's website,
    they will be redirected back to this URL to finish the process."""

    oauth_verifier = request.args.get('oauth_verifier', '')

    token = oauth.Token(session['oauth_token'], session['oauth_token_secret'])
    token.set_verifier(oauth_verifier)

    client = get_oauth_client()
    client = get_oauth_client(token)

    # Retrieve the token credentials (Access Token) from Evernote
    resp, content = client.request(EN_ACCESS_TOKEN_URL, 'POST')

    if resp['status'] != '200':
        return render_template("en_error.html")

    access_token = dict(urlparse.parse_qsl(content))
    authToken = access_token['oauth_token']

    userStore = get_userstore()
    user = userStore.getUser(authToken)

    # Save the users information to so we can make requests later
    session['shardId'] = user.shardId
    session['identifier'] = authToken

    return redirect("/fotopedia_auth")


@app.route("/fotopedia_auth", methods=['POST','GET'])
def fotopedia_auth():
	if request.method == "GET":
		return render_template("login_fotopedia.html")
	elif request.method == "POST":
		if request.form['fotopedia-user-email'] and request.form['password']:
			username=request.form['fotopedia-user-email']
			password=request.form['password']
			
			try:
				all_ids=get_draft_stories_ids(username, password)+get_published_stories_ids(username, password)
			except Exception as err:
				if err == 6 or err == 7:
					return render_template("go_premium.html")
				return render_template("login_error.html")
			session['fotopedia_username']=username
			session['fotopedia_password']=password
			session['num_of_stories']=len(all_ids)

			return redirect("/transfer")
		else:
			return render_template("login_error.html")

@app.route("/transfer", methods=['GET','POST'])
def transfer():
	if request.method == "GET":
		return render_template("transfer.html", num_of_stories=session['num_of_stories'])
	elif request.method == "POST":
		try:
			username=session['fotopedia_username']
			password=session['fotopedia_password']
			session['num_of_stories']
			all_ids=get_draft_stories_ids(username, password)+get_published_stories_ids(username, password)
		except:
			"you didn't get far \n\n\n\n\\"
			return render_template("login_error.html")	
		try:
			for _id in all_ids:
				if not sync_fotopedia_id(_id):
					print "\n\nERROR: id"+_id+"not synced\n\n"
		except Exception as err:
				if err.errorCode == 6 or err.errorCode == 7:
					return render_template("go_premium.html")
				return render_template("login_error.html")

		return redirect("/success")
	else:
		return render_template("login_error.html")	



@app.route("/success", methods=['GET'])
def success():
	#view in evernote account online/in app
	#postachio
	#fastpencil

	return render_template("success.html")

@app.route("/go_premium", methods=['GET'])
def go_premium():
	#view in evernote account online/in app
	#postachio
	#fastpencil

	return render_template("go_premium.html")
	



if __name__ == '__main__':
    app.secret_key = APP_SECRET_KEY
    app.run(host='0.0.0.0', debug=True, port=8080)
