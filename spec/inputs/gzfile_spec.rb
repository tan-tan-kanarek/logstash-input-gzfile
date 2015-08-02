# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "tempfile"
require "stud/temporary"
require "logstash/inputs/gzfile"

describe "inputs/gzfile" do

	delimiter = (LogStash::Environment.windows? ? "\r\n" : "\n")

	it "should starts at the end of an existing file" do
		tmpfile_path = Stud::Temporary.pathname
		sincedb_path = Stud::Temporary.pathname

		conf = <<-CONFIG
      input {
        gzfile {
          type => "blah"
          path => "#{tmpfile_path}"
          sincedb_path => "#{sincedb_path}"
          delimiter => "#{delimiter}"
        }
      }
		CONFIG

		File.open(tmpfile_path, 'w') do |f|
			gz = Zlib::GzipWriter.new(f)
			gz.puts("ignore me 1")
			gz.puts("ignore me 2")
			gz.close
		end

		events = input(conf) do |pipeline, queue|

			# at this point the plugins
			# threads might still be initializing so we cannot know when the
			# file plugin will have seen the original file, it could see it
			# after the first(s) hello world appends below, hence the
			# retry logic.

			events = []

			retries = 0
			while retries < 20
				File.open(tmpfile_path, 'a') do |f|
					Zlib::GzipWriter.wrap(f) do |gz|
						gz.puts("hello")
						gz.puts("world")
						gz.close
					end
				end

				if queue.size >= 2
					events = 2.times.collect { queue.pop }
					break
				end

				sleep(0.1)
				retries += 1
			end

			events
		end

		insist { events[0]["message"] } == "hello"
		insist { events[1]["message"] } == "world"
	end

	it "should start at the beginning of an existing file" do
		tmpfile_path = Stud::Temporary.pathname
		sincedb_path = Stud::Temporary.pathname

		conf = <<-CONFIG
      input {
        gzfile {
          type => "blah"
          path => "#{tmpfile_path}"
          start_position => "beginning"
          sincedb_path => "#{sincedb_path}"
          delimiter => "#{delimiter}"
        }
      }
		CONFIG

		File.open(tmpfile_path, 'a') do |f|
			Zlib::GzipWriter.wrap(f) do |gz|
				gz.puts("hello")
				gz.puts("world")
				gz.close
			end
		end

		events = input(conf) do |pipeline, queue|
			2.times.collect { queue.pop }
		end

		insist { events[0]["message"] } == "hello"
		insist { events[1]["message"] } == "world"
	end

	it "should restarts at the sincedb value" do
		tmpfile_path = Stud::Temporary.pathname
		sincedb_path = Stud::Temporary.pathname

		conf = <<-CONFIG
      input {
        gzfile {
          type => "blah"
          path => "#{tmpfile_path}"
          start_position => "beginning"
          sincedb_path => "#{sincedb_path}"
          delimiter => "#{delimiter}"
        }
      }
		CONFIG

		File.open(tmpfile_path, 'w') do |f|
			gz = Zlib::GzipWriter.new(f)
			gz.puts("hello3")
			gz.puts("world3")
			gz.close
		end

		events = input(conf) do |pipeline, queue|
			2.times.collect { queue.pop }
		end

		insist { events[0]["message"] } == "hello3"
		insist { events[1]["message"] } == "world3"

		File.open(tmpfile_path, 'a') do |f|
			Zlib::GzipWriter.wrap(f) do |gz|
				gz.puts("foo")
				gz.puts("bar")
				gz.puts("baz")
				gz.close
			end
		end

		events = input(conf) do |pipeline, queue|
			3.times.collect { queue.pop }
		end

		insist { events[0]["message"] } == "foo"
		insist { events[1]["message"] } == "bar"
		insist { events[2]["message"] } == "baz"
	end

	it "should not overwrite existing path and host fields" do
		tmpfile_path = Stud::Temporary.pathname
		sincedb_path = Stud::Temporary.pathname

		conf = <<-CONFIG
      input {
        gzfile {
          type => "blah"
          path => "#{tmpfile_path}"
          start_position => "beginning"
          sincedb_path => "#{sincedb_path}"
          delimiter => "#{delimiter}"
          codec => "json"
        }
      }
		CONFIG

		File.open(tmpfile_path, 'w') do |f|
			gz = Zlib::GzipWriter.new(f)
			gz.puts('{"path": "my_path", "host": "my_host"}')
			gz.puts('{"my_field": "my_val"}')
			gz.close
		end

		events = input(conf) do |pipeline, queue|
			2.times.collect { queue.pop }
		end

		insist { events[0]["path"] } == "my_path"
		insist { events[0]["host"] } == "my_host"

		insist { events[1]["path"] } == "#{tmpfile_path}"
		insist { events[1]["host"] } == "#{Socket.gethostname.force_encoding(Encoding::UTF_8)}"
	end

	context "when sincedb_path is an existing directory" do
		let(:tmpfile_path) { Stud::Temporary.pathname }
		let(:sincedb_path) { Stud::Temporary.directory }
		subject { LogStash::Inputs::File.new("path" => tmpfile_path, "sincedb_path" => sincedb_path) }

		after :each do
			FileUtils.rm_rf(sincedb_path)
		end

		it "should raise exception" do
			expect { subject.register }.to raise_error(ArgumentError)
		end
	end
end
