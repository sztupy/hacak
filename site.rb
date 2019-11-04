# frozen_string_literal: true

require 'sinatra'
require "sinatra/cookies"
require 'json'
require 'jwt'
require 'base64'
require "openssl"
require "digest"
require 'securerandom'

$rsa_private = OpenSSL::PKey::RSA.generate 2048
$rsa_public = $rsa_private.public_key
$aes_key = SecureRandom.random_bytes(32)

def aes256_cbc_encrypt(key, data, iv)
  key = Digest::SHA256.digest(key) if(key.kind_of?(String) && 32 != key.bytesize)
  iv = Digest::MD5.digest(iv) if(iv.kind_of?(String) && 16 != iv.bytesize)
  aes = OpenSSL::Cipher.new('AES-256-CBC')
  aes.encrypt
  aes.key = key
  aes.iv = iv
  aes.update(data) + aes.final
end

def aes256_cbc_decrypt(key, data, iv)
  key = Digest::SHA256.digest(key) if(key.kind_of?(String) && 32 != key.bytesize)
  iv = Digest::MD5.digest(iv) if(iv.kind_of?(String) && 16 != iv.bytesize)
  aes = OpenSSL::Cipher.new('AES-256-CBC')
  aes.decrypt
  aes.key = key
  aes.iv = iv
  aes.update(data) + aes.final
end

class Site < Sinatra::Base
  helpers Sinatra::Cookies

  enable :sessions

  configure :production, :development do
    enable :logging
  end

  get '/' do
    @notice = session[:notice]
    session[:notice] = nil
    erb :index
  end

  post '/logout' do
    session.clear
    cookies.clear
    session[:notice] = "Logout successful"
    redirect to('/')
  end

  post '/login' do
    if params[:username] != 'admin'
      if params[:username].to_s.downcase =~ /'\s+or\s+''='/
        session[:login] = 'Admin #6'
        session[:notice] = "Congratulations you are an admin (code <code>#C6E409</code>)"
      else
        session[:notice] = "Invalid username or password"
      end
    else
      if params[:password] == 'hunter'
        session[:login] = 'Admin #1'
        session[:notice] = "Congratulations you are an admin (code <code>#EF6018</code>)"
      elsif params[:password] == "8iCis6q6aPZ6-mHbZkkN"
        session[:login] = 'Admin #2'
        session[:notice] = "Congratulations you are an admin (code <code>#3FD34B</code>)"
      elsif params[:password] == "ShPPBc2iifXCxWgW27jX"
        session[:login] = 'Admin #5'
        session[:notice] = "Congratulations you are an admin (code <code>#BA9ADC</code>)"
      elsif params[:password] == "vGtBDdpXagVyMw-M9GRb"
        session[:login] = 'Admin #8'
        session[:notice] = "Congratulations you are an admin (code <code>#AA128E</code>)"
      else
        session[:notice] = "Invalid username or password"
      end
    end
    redirect to('/')
  end

  get '/admin' do
    if session[:login] == 'guest'
      session[:login] = 'Admin #4'
      session[:notice] = "Congratulations you are an admin (code <code>#D28157</code>)"
    end
    redirect to('/')
  end

  get '/guest' do
    if params[:admin].to_s == '1'
      session[:login] = 'Admin #3'
      session[:notice] = "Congratulations you are an admin (code <code>#A9E4EA</code>)"
    else
      session[:notice] = "Logged in as guest"
      session[:login] = 'guest'

      jwt = JWT.encode({admin:0}, $rsa_private, 'RS256')
      cookies[:jwt] = jwt

      iv = SecureRandom.random_bytes(16)
      data = '{"admin":"0"}'
      token = aes256_cbc_encrypt($aes_key,data,iv)

      cookies[:token] = iv.each_byte.map{|byte| "%02x" % [byte]}.join +
                        token.each_byte.map{|byte| "%02x" % [byte]}.join
    end
    redirect to('/')
  end

  get '/avatar' do
    if params[:url] == 'guest.png'
      send_file File.join('public','guest.png')
    elsif params[:url] == 'admin.png'
      send_file File.join('public','admin.png')
    elsif params[:url] == '../../../etc/passwd'
      'admin:ShPPBc2iifXCxWgW27jX:1000:100:Admin,Admin,Admin,Admin,Admin:/home/admin:/bin/bash'
    else
      send_file File.join('public','404.html')
    end
  end

  get '/jwt' do
    begin
      decoded_token = JWT.decode(params[:jwt], nil, false)

      algorithm = 'RS256'
      if decoded_token[1]['alg'] == 'HS256'
        key_data = $rsa_public.to_s.gsub(/-----BEGIN PUBLIC KEY-----/,'').gsub(/-----END PUBLIC KEY-----/,'').gsub(/\s/,'').strip
        decoded_token = JWT.decode(params[:jwt], Base64.decode64(key_data), true, { algorithm: 'HS256' })
      else
        decoded_token = JWT.decode(params[:jwt], $rsa_public, true, { algorithm: 'RS256' })
      end

      if decoded_token[0]['admin'].to_s == '1'
        "Admin #9; Congratulations you are an admin (code <code>#3FAB39</code>)"
      else
        "Valid Token. Not Admin"
      end
    rescue => e
      "Invalid Token: #{e}"
    end
  end

  get '/token' do
    begin
      input = [params[:token]].pack('H*')
      iv = input[0...16]
      data = input[16..-1]

      token = JSON.parse(aes256_cbc_decrypt($aes_key,data,iv))

      if token['admin'].to_s == '1'
        "Admin #10; Congratulations you are an admin (code <code>#9AF195</code>)"
      else
        "Valid Token. Not Admin"
      end
    rescue OpenSSL::Cipher::CipherError => e
      "Invalid Token: Padding Error"
    rescue => e
      "Invalid Token: #{e}"
    end
  end

  not_found do
    send_file File.join('public','404.html')
  end
end

# ===============================================
# Welcome Admin #7!
# Congratulations you are an admin (code #D1F207)
# ===============================================
