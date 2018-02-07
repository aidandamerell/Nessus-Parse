#!/usr/bin/env ruby

require 'ruby-nessus'
require 'nmap'
require 'trollop'
require 'pp'
require 'csv'
require 'yaml'
require 'tty-command'
require 'threadify'

class Sslhost
	attr_accessor :ip, :ports
	@@all_hosts = []

	def initialize(ip)
		@ip = ip
		@ports = {}
		@@all_hosts << self
	end

	def self.all_hosts
		@@all_hosts
	end
end


opts = Trollop::options do
	opt :csv, "Output to CSV", :type => :string
	opt :nessus, "Nessus XML", :type => :string
	opt :liveiponly, "Output to screen hosts with at least one open port"
	opt :threads, "Number of threads to run", :type => :integer, :default => 3
end


RubyNessus::Parse.new(opts[:nessus]) do |scan|
	puts "Hosts in file: #{scan.host_count}"
	scan.hosts.each do |host|
		h = Sslhost.new(host.ip)
		unless host.event_count.nil?
			host.events.select { |x| x.plugin_id == 56984 }.each do |ssltls|
				h.ports[ssltls.port.number.value] = ""
			end
		end
	end
end

Sslhost.all_hosts.threadify(opts[:threads]) {|host|
	unless host.ports.empty?
		puts "Doing host: #{host.ip}"
		host.ports.each do |port, data|
			output = ''
			cmd = TTY::Command.new(output: output)
			connection = cmd.run!("sslscan", "--no-color", "#{host.ip}\:#{port}")
			host.ports[port] = connection.out
		end
	end
}

if opts[:csv]
	CSV.open(opts[:csv] + ".csv", "w+") do |csv|
		csv << ["IP", "Port", "Output"]
		Sslhost.all_hosts.each do |host|
			host.ports.each do |port, data|
				csv << [host.ip, port, data]
			end
		end
	end
end