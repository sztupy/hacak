#\ -p 8094
# frozen_string_literal: true

require 'rubygems'
require 'bundler'

Bundler.require

require './site'

run Site
