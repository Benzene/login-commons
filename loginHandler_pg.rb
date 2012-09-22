#!/usr/bin/env ruby

require 'sinatra'
require 'pg'
require 'bcrypt'
require 'haml'
require 'rack/csrf'

dbname = "common_users"
dbuser = "common_users"
dbpass = "common_users"

enable :inline_templates

class AuthenticationError < StandardError; end
class ParameterError < StandardError; end

use Rack::Session::Pool, :expire => 60 * 60 * 24
use Rack::Csrf, :raise => true

error AuthenticationError do
	"Authentication failed !"
	redirect url('/login')
end

error ParameterError do
	"Wrong parameters given !"
end

helpers do
	def is_authed?
		!session[:user].nil?
	end
	def auth(user, pass)
		raise AuthenticationError, 'No credentials given' unless (user.is_a?(String) && pass.is_a?(String))
		pair = [ user ]
		res = @auth_db.exec('SELECT hashed_pass FROM users WHERE "username"=$1', pair)
		raise AuthenticationError, 'Invalid credentials (username not found)' unless res.ntuples > 0
		raise AuthenticationError, 'Invalid credentials (wrong password)' unless BCrypt::Password.new(res[0]['hashed_pass']) == pass
		session[:user] = user
	end
	def require_auth
		if !is_authed? then
			redirect url('/login')
		end
	end
	def require_non_auth
		if is_authed? then
			redirect url('/')
		end
	end
end

before do
    @auth_db = PGconn.open(:dbname => dbname, :user => dbuser, :password => dbpass)
end

# An usage example :
#get '/' do
#	require_auth
#	pair = [ session[:user] ]
#end

get '/login' do
	require_non_auth
	haml :login
end

post '/login' do
	require_non_auth
	auth(params[:user], params[:pass])
	is_authed?
	redirect url('/')
end

get '/register' do
	require_non_auth
	haml :register
end

post '/register' do
	require_non_auth
	pair = [ params[:user], BCrypt::Password.create(params[:pass]), params[:email] ]
    begin
	    @auth_db.exec('INSERT INTO users (username,hashed_pass,email) VALUES($1,$2,$3)', pair)
    rescue PG::Error => e
        puts e.message
        puts e.backtrace.inspect
        redirect url('/register')
    end
	redirect url('/')
end

get '/logout' do
	session[:user] = nil
	redirect url('/')
end

__END__

@@ login
%form{:action => url('/login'), :method => "post"}
  User :
  %input{:type => "text", :name => "user"}
  %br
  Password :
  %input{:type => "password", :name => "pass"}
  %br
  = Rack::Csrf.tag(env)
  %input{:type => "submit"}
  :markdown
    No account ? Try to [register](/register "Register") first !

@@ register
%form{:action => url('/register'), :method => "post"}
  User :
  %input{:type => "text", :name => "user"}
  %br
  Email :
  %input{:type => "text", :name => "email"}
  %br
  Password :
  %input{:type => "password", :name => "pass"}
  = Rack::Csrf.tag(env)
  %br
  %input{:type => "submit"}

