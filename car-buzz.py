import os
import re
import random
import hashlib
import hmac
import cgi
from string import letters

import time
import datetime

import urllib
import urllib2
import httplib
import json
from xml.dom import minidom

import base64

import webapp2
import jinja2

from twilio import twiml
from twilio.rest import TwilioRestClient

# from google.appengine.api import oauth
from google.appengine.api import urlfetch
# from google.appengine.api import memcache

from google.appengine.ext import db
from google.appengine.ext import ndb

# from google.appengine.api import users

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


# admins = ['svanbrunt', 'nancyvanbrunt', 'unsworth', 'vanunsworth']
admins = [5838406743490560, 5707702298738688, 5629499534213120]
delete_password = 'shred'

secret = 'shred'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def send_sms(to, body):
	car_buzz_sms = "(415) 319-6999"
	account_sid = "AC4ae9a03eaba7f8d8f05c1a7a86ace6ec"
	auth_token = "678466e74045efef01de45fbfac63394"
	client = TwilioRestClient(account_sid, auth_token)
	message = client.messages.create(to=to, from_=car_buzz_sms, body=body)


class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class Home(MainHandler):
	def get(self):
		self.render("home.html") 

class NewPlate(MainHandler):
	def get(self):
		if self.user:
			self.render("newplate.html")
		else:
			self.redirect('/login')
	
	def post(self):
		error = ""

		state = self.request.get('state')
		plate = self.request.get('plate').upper() #get plate and capitalize
		plate = plate.replace(" ","") # remove any spaces from plate number
		
		phone = self.user.phone

		user_id = self.user.key().id_or_name()

		if plate and state and phone:

			# regular expression to check valid phone #; if not, re-render the form
			if not valid_tel(phone):
				error_tel = "Doesn't look like a valid phone number."
				self.render("newplate.html", nickname=nickname, user_id=user_id, user=user, state=state, plate=plate, phone=phone, error=error, error_tel=error_tel)

			# construct unique variables + put into DB
			else:
				unique_plate = state + "_" + plate

				p = LicensePlates(
						user_id=user_id,
						unique_plate=unique_plate,
						state=state,
						plate=plate,
						phone=phone,
					)
				p.put()
				self.redirect("/profile")

		else:
			error = "All inputs (plate & state) are required."
			self.render("newplate.html", state=state, plate=plate, error=error)


class Report(MainHandler):
	def get(self):
		# user = users.get_current_user()
		message = self.request.get("message")
		
		self.render("report4.html",
				messeage = message)

	def post(self):
		reporter = self.user.phone

		state = self.request.get("state")

		plate = self.request.get("plate").upper()
		plate = plate.replace(" ","") #REMOVE ANY SPACES

		# CREATE UNIQUE PLATE
		if state and plate: 
			unique_plate = state + "_" + plate

		status = self.request.get("status")
		incident = self.request.get("incident")
		
		notes = self.request.get("notes")

		# BUILD MESSAGE BODY WIHT NOTES
		if notes:
			body = "Someone has reported that your car " + status + " " + incident + ".  Notes: " + notes
		else:
			notes = ""
			body = "Someone has reported that your car " + status + " " + incident + "."

		# CHECK HAVE ALL ELEMENTS 
		if state and plate and (status != 'NULL') and (incident != 'NULL'):
			unique_plate = state + "_" + plate
			plates = LicensePlates.all()
			plates.filter("unique_plate =", unique_plate)
			entries = plates.fetch(10)  # Up to 10 results for that unique plate

			# IF NOBODY HAS REGISTERED THAT PLATE
			if not entries:
				message = "Sorry - we couldn't find that plate." 
				sub_message = "Be a #NeibhorhoodHero and share CurbKarma with the world so others add their plate."
				result = "no entry"
				
				r = Reports(
						reporter=reporter,
						unique_plate=unique_plate,
						state=state,
						plate=plate,
						# phone=phone,
						status=status,
						incident=incident,
						notes=notes,
						result=result
					)
				r.put()

				self.render("confirm.html", 
					message=message,
					sub_message=sub_message
					)

				# GIVE ADMIN A NOTICE (BY TEXT)
				# for entry in admin_phone:
				# 	i = 0
				# 	body_admin = ""
				# 	try:
				# 		phone_admin = entry[i]
				# 	i++

			# IF SOMEONE HAS REGISTERED THAT PLATE
			else:
				# i = 1
				# j = len(entries)
				for entry in entries:
					# phone = entry.phone
					# SVB LOOK HERE --> 
					phone = entry.phone  
					body = body #+ " (recipent %s of %s)" % (i, j)
					# body = body + " (recipent %s)" % (i)
					try:
						send_sms(phone, body)
						result = "success"
						# i = i + 1
					
					# Error handling here -  callback URL to twilio
					except:
						result = "failure"
					# 	message = "Sorry - something went wrong"
					# 	self.render("confirm.html", 
					# 		message=message
					# 		)

					# WRITE THAT INCIDENT WAS REPORTED
					r = Reports(
							nickname=reporter,
							unique_plate=unique_plate,
							state=state,
							plate=plate,
							phone=phone,
							status=status,
							incident=incident,
							notes=notes,
							result=result
						)
					r.put()

				message = "Sucess!" 
				sub_message = "We just sent a text to the owner of " + state + " license plate " + plate + "."

				self.render("confirm.html", 
					message=message,
					sub_message=sub_message
					)

		else:
			if not plate:
				plate = ""

			message = "Please provide both the plate info and what the issue is."
			
			self.render("report4.html", 
				message=message, 
				state=state, 
				plate=plate,
				status=status,
				incident=incident, 
				notes=notes
				)

class Confirm(MainHandler):
	def get(self):
		# state = "CA"
		# plate = "ABCDE"
		message = "Sucess!  We just sent a text to the owner of " + state + " license plate " + plate + "."
		self.render("confirm.html", message=message)


class Nuke(MainHandler):
  def get(self):
    user = users.get_current_user()
    nickname = user.nickname()

    self.render("delete.html",
                nickname=nickname,
                )
	# HTML FOR DELETE PAGE

  def post(self):
    user = users.get_current_user()
    nickname = user.nickname()

    delete_code = self.request.get('delete_code')
    
    if delete_code:
      if delete_code == delete_password:
        # l = LicensePlates.all()
        # db.delete(l)

        k = Reported.all()
        db.delete(k)

      else:
        error = "Incorrect password.  Who are you?!"
        self.render('delete.html',
                    error=error,
                    nickname=nickname
                    )

    else:
      error = "You need the code."
      self.render('delete.html',
                  error=error,
                  nickname=nickname
                  )


class Profile(MainHandler):
	def get(self):

		if self.user:
			phone = self.user.phone

			# GET all plates for this user
			p = LicensePlates.all()
			p.filter("phone =", phone)

			# test = json(p)
			# GET all reported incidents of their plates
			# for p.plate in p:
			# 	i = 0
			# 	r = Reported.all()
			# 	r.filter("plate =", p.plate)
			# 	i = i + 1

			self.render("profile3.html",
				p=p
				)

		else:
			self.redirect("/login")


class Admin(MainHandler):
	def get(self):

		if self.user:
			# if int(self.user.key().id_or_name()) in admins:
			# user_id = int(self.user.key().id_or_name())
			# var_type = type(user_id)
			q = LicensePlates.all()
			r = Reports.all()
			s = User.all()
			self.render("admin.html"
				, q=q
				, r=r
				, s=s
				# , user_id=user_id
				# , var_type=var_type
				)
			# else:
			# 	message = "Please log in as an admin; insufficient privleges"
			# 	self.render("admin.html", message=message)


		else:
			self.redirect('/login')


class Edit(MainHandler):
	def get(self):

		plate = self.request.get("plate")
		state = self.request.get("state")
		phone = self.request.get("phone")

		self.render("edit.html", 
			plate=plate,
			state=state,
			phone=phone
			)	

	def post(self):

		# SVB LOOK HERE
		state = self.request.get("state")
		plate = self.request.get("plate")
		# user_id = self.request.get("id")
		# user_plate = self.request.get("user_plate")

		user_id = self.user.key().id_or_name()
		unique_plate = state + "_" + plate

		d = LicensePlates.all()
		d.filter("user_id =", user_id)
		d.filter("unique_plate =", unique_plate)
		db.delete(d)

		# self.render("edit.html",
		# 	user_id=user_id,
		# 	unique_plate=unique_plate,
		# 	d=d)

		url = '/profile'
		self.redirect(url)


class About(MainHandler):
	def get(self):
		self.render("about.html")


class SignUp(MainHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False

		phone = self.request.get('phone')
		password = self.request.get('password')
		verify = self.request.get('verify')

		params = dict()
		# params['phone'] = phone

		if not valid_pin(password):
			params['error_password'] = "Must be a 4-digit PIN"
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_tel(phone):
			params['error_phone'] = "That's not a valid phone number."
			have_error = True

		if have_error:
			self.render('signup-form.html', phone=phone, **params)
		else:
			self.done(password, phone)

	def done(self, password, phone):
		u = User.by_phone(phone)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_user = msg)
		else:
			u = User.register(phone, password)
			u.put()

			self.login(u)
			self.redirect('/profile')


class Login(MainHandler):
	def get(self): 
		self.render("login-form.html")

	def post(self):
		phone = self.request.get("phone")
		password = self.request.get("password")

		u = User.login(phone, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)


class Forgot(MainHandler):
	def get(self):
		self.render("forgot.html")

	def post(self):
		phone = self.request.get("phone")

		#Lookup user by phone number
		u = User.by_phone(phone)

		if u:
			# User's unique ID
			user_id = u.key().id_or_name()

			# Create a unique key for the reset request
			rk = reset_key()

			# put those in the db
			r = Resets(
				reset_key =rk,
				user_id = user_id)
			r.put()

			time.sleep(0.25) 

			url = '/reset?key=' + rk + '&id=' + str(user_id)
			self.redirect(url)	

		else:
			error = "Sorry that phone number is not registered."
			self.render("forgot.html",
				error=error)


class Reset(MainHandler):
	def get(self):

		# Check to ensure valid URL based on key + id match
		rk = self.request.get("key")
		user_id = int(self.request.get("id"))

		# match = Resets.by_key(rk).count()

		match = Resets.all()
		match = match.filter("reset_key =", rk)
		length = match.count()

		#Make sure there was at least 1 match
		if length > 0:
			
			# Get User ID that corresponds to that Reset_Key in the DB
			m = match.get()
			match_id = m.user_id

			# Confirm that User ID matches from DB
			if user_id == match_id:

				self.render("reset.html"
					# , m = m
					# , rk = rk
					# , length = length
					# , match_id = match_id
					, user_id = user_id
					# , reset_key = reset_key 
					)

			else:
				self.redirect('/forgot')

		else:
			self.redirect('/forgot')


	def post(self):
		have_error = False

		user_id = int(self.request.get("id"))

		password = self.request.get('password')
		verify = self.request.get('verify')

		params = dict()
		# params['phone'] = phone

		if not valid_pin(password):
			params['error_password'] = "Must be a 4-digit PIN"
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if have_error:
			# self.render('reset.html', **params)
			self.redirect('/')

		else:
			u = User.by_id(user_id)
			# u = u.get()
			# length = u.count
			phone = u.phone

			# u = User.register(phone, password)
			pw_hash = make_pw_hash(phone, password)

			u.pw_hash = pw_hash
			u.put()
			
			self.redirect('/login')

			# self.render("reset.html"
			# 	# , length = length
			# 	, u = u
			# 	, phone = phone
			# 	, user_id = user_id
			# 	)




class Logout(MainHandler):
    def get(self):
    	self.logout()
    	self.redirect('/')




# DATABASES

class User(db.Model):
	phone = db.PhoneNumberProperty()
	pw_hash = db.StringProperty()
	modified = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_phone(cls, phone):
		u = User.all().filter('phone =', phone).get()
		return u	

	@classmethod
	def register(cls, phone, pw):
		pw_hash = make_pw_hash(phone, pw)
		return User(parent = users_key(),
			phone = phone,
			pw_hash = pw_hash
			)

	@classmethod
	def login(cls, phone, pw):
		u = cls.by_phone(phone)
		if u and valid_pw(phone, pw, u.pw_hash):
			return u


class Resets(db.Model):
	reset_key = db.StringProperty()
	user_id = db.IntegerProperty()
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_key(cls, key):
		return Resets.all().filter("reset_key =", key)

     
class LicensePlates(db.Model):
	user_id = db.IntegerProperty()
	unique_plate = db.StringProperty()
	state = db.StringProperty()
	plate = db.StringProperty()
	phone = db.PhoneNumberProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)


class Reported(db.Model):
	# Name = db.StringProperty()
	# user_id = db.StringProperty()
	nickname = db.StringProperty()
	unique_plate = db.StringProperty()
	state = db.StringProperty()
	plate = db.StringProperty()
	phone = db.PhoneNumberProperty()
	status = db.StringProperty()
	incident = db.StringProperty()
	notes = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)


class Reports(db.Model):
	# user_id = db.StringProperty()
	reporter = db.StringProperty()
	# unique_plate = db.StringProperty()
	state = db.StringProperty()
	plate = db.StringProperty()
	phone = db.PhoneNumberProperty()
	status = db.StringProperty()
	incident = db.StringProperty()
	notes = db.StringProperty()
	result = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)





def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(phone, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(phone + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)


def reset_key(length = 10):
    return ''.join(random.choice(letters) for x in xrange(length))


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

PIN_RE = re.compile(r"\d{4}")
def valid_pin(pin):
	return pin and PIN_RE.match(pin)

TEL_RE = re.compile(r"\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4}")
def valid_tel(tel):
	return tel and TEL_RE.match(tel)




app = webapp2.WSGIApplication([
	('/', Home)
    ,('/report', Report)
    ,('/newplate', NewPlate)
    ,('/profile', Profile)
    ,('/edit', Edit)
    ,('/report', Report)    
    ,('/confirm', Confirm)
    ,('/signup', SignUp)
    ,('/login', Login)
    ,('/logout', Logout)
    ,('/forgot', Forgot)
    ,('/reset', Reset)
    ,('/admin', Admin)
    ,('/about', About)
    ,('/nuke', Nuke)
	], debug=True)
