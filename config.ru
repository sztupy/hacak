#\ -p 8094 --host 0.0.0.0 -s puma
# frozen_string_literal: true

require 'rubygems'
require 'bundler'

Bundler.require

require './site'

run Site
