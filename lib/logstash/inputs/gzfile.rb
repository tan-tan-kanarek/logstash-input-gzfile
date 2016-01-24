# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "pathname"
require "socket" # for Socket.gethostname

# BufferedTokenizer takes a delimiter upon instantiation, or acts line-based
# by default.  It allows input to be spoon-fed from some outside source which
# receives arbitrary length datagrams which may-or-may-not contain the token
# by which entities are delimited.  In this respect it's ideally paired with
# something like EventMachine (http://rubyeventmachine.com/).
class GzBufferedTokenizer
  # New BufferedTokenizers will operate on lines delimited by a delimiter,
  # which is by default the global input delimiter $/ ("\n").
  #
  # The input buffer is stored as an array.  This is by far the most efficient
  # approach given language constraints (in C a linked list would be a more
  # appropriate data structure).  Segments of input data are stored in a list
  # which is only joined when a token is reached, substantially reducing the
  # number of objects required for the operation.
  def initialize(delimiter = $/)
    @delimiter = delimiter
    @input = []
    @tail = ''
    @trim = @delimiter.length - 1
  end

  # Extract takes an arbitrary string of input data and returns an array of
  # tokenized entities, provided there were any available to extract.  This
  # makes for easy processing of datagrams using a pattern like:
  #
  #   tokenizer.extract(data).map { |entity| Decode(entity) }.each do ...
  #
  # Using -1 makes split to return "" if the token is at the end of
  # the string, meaning the last element is the start of the next chunk.
  def extract(data)
    if @trim > 0
      tail_end = @tail.slice!(-@trim, @trim) # returns nil if string is too short
      data = tail_end + data if tail_end
    end

    @input << @tail
    entities = data.split(@delimiter, -1)
    @tail = entities.shift

    unless entities.empty?
      @input << @tail
      entities.unshift @input.join
      @input.clear
      @tail = entities.pop
    end

    entities
  end

  # Flush the contents of the input buffer, i.e. return the input buffer even though
  # a token has not yet been encountered
  def flush
    @input << @tail
    buffer = @input.join
    @input.clear
    @tail = "" # @tail.clear is slightly faster, but not supported on 1.8.7
    buffer
  end
end

class GzWatch
  attr_accessor :logger

  public
  def initialize(opts={})
    @iswindows = ((RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/) != nil)
    if opts[:logger]
      @logger = opts[:logger]
    else
      @logger = Logger.new(STDERR)
      @logger.level = Logger::INFO
    end
    @watching = []
    @exclude = []
    @files = Hash.new { |h, k| h[k] = Hash.new }
  end # def initialize

  public
  def logger=(logger)
    @logger = logger
  end

  public
  def exclude(path)
    path.to_a.each { |p| @exclude << p }
  end

  public
  def watch(path)
    if ! @watching.member?(path)
      @watching << path
      _discover_file(path, true)
    end

    return true
  end # def watch

  public
  def inode(path,stat)
    if @iswindows
      fileId = Winhelper.GetWindowsUniqueFileIdentifier(path)
      inode = [fileId, stat.dev_major, stat.dev_minor]
    else
      inode = [stat.ino.to_s, stat.dev_major, stat.dev_minor]
    end
    return inode
  end

  # Calls &block with params [event_type, path]
  # event_type can be one of:
  #   :create_initial - initially present file (so start at end for tail)
  #   :create - file is created (new file after initial globs, start at 0)
  #   :modify - file is modified (size increases)
  #   :delete - file is deleted
  public
  def each(&block)
    # Send any creates.
    @files.keys.each do |path|
      if ! @files[path][:create_sent]
        if @files[path][:initial]
          yield(:create_initial, path)
        else
          yield(:create, path)
        end
        @files[path][:create_sent] = true
      end
    end

    @files.keys.each do |path|
      begin
        stat = File::Stat.new(path)
      rescue Errno::ENOENT
        # file has gone away or we can't read it anymore.
        @files.delete(path)
        @logger.debug? && @logger.debug("#{path}: stat failed (#{$!}), deleting from @files")
        yield(:delete, path)
        next
      end

      inode = inode(path,stat)
      if inode != @files[path][:inode]
        @logger.debug? && @logger.debug("#{path}: old inode was #{@files[path][:inode].inspect}, new is #{inode.inspect}")
        yield(:delete, path)
        yield(:create, path)
      elsif stat.size < @files[path][:size]
        @logger.debug? && @logger.debug("#{path}: file rolled, new size is #{stat.size}, old size #{@files[path][:size]}")
        yield(:delete, path)
        yield(:create, path)
      elsif stat.size > @files[path][:size]
        @logger.debug? && @logger.debug("#{path}: file grew, old size #{@files[path][:size]}, new size #{stat.size}")
        yield(:modify, path)
      end

      @files[path][:size] = stat.size
      @files[path][:inode] = inode
    end # @files.keys.each
  end # def each

  public
  def discover
    @watching.each do |path|
      _discover_file(path)
    end
  end

  public
  def subscribe(stat_interval = 1, discover_interval = 5, &block)
    glob = 0
    @quit = false
    while !@quit
      each(&block)

      glob += 1
      if glob == discover_interval
        discover
        glob = 0
      end

      sleep(stat_interval)
    end
  end # def subscribe

  private
  def _discover_file(path, initial=false)
    globbed_dirs = Dir.glob(path)
    @logger.debug? && @logger.debug("_discover_file_glob: #{path}: glob is: #{globbed_dirs}")
    if globbed_dirs.empty? && File.file?(path)
      globbed_dirs = [path]
      @logger.debug? && @logger.debug("_discover_file_glob: #{path}: glob is: #{globbed_dirs} because glob did not work")
    end
    globbed_dirs.each do |file|
      next if @files.member?(file)
      next unless File.file?(file)

      @logger.debug? && @logger.debug("_discover_file: #{path}: new: #{file} (exclude is #{@exclude.inspect})")

      skip = false
      @exclude.each do |pattern|
        if File.fnmatch?(pattern, File.basename(file))
          @logger.debug? && @logger.debug("_discover_file: #{file}: skipping because it " +
                        "matches exclude #{pattern}")
          skip = true
          break
        end
      end
      next if skip

      stat = File::Stat.new(file)
      @files[file] = {
        :size => 0,
        :inode => inode(file,stat),
        :create_sent => false,
        :initial => initial
      }
    end
  end # def _discover_file

  public
  def quit
    @quit = true
  end # def quit
end # class GzWatch

class GzTail
  # how often (in seconds) we @logger.warn a failed file open, per path.
  OPEN_WARN_INTERVAL = ENV["FILEWATCH_OPEN_WARN_INTERVAL"] ?
                       ENV["FILEWATCH_OPEN_WARN_INTERVAL"].to_i : 300

  attr_accessor :logger

  class NoSinceDBPathGiven < StandardError; end

  public
  def initialize(opts={})
    @iswindows = ((RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/) != nil)

    if opts[:logger]
      @logger = opts[:logger]
    else
      @logger = Logger.new(STDERR)
      @logger.level = Logger::INFO
    end
    @files = {}
    @lastwarn = Hash.new { |h, k| h[k] = 0 }
    @buffers = {}
    @watch = GzWatch.new
    @watch.logger = @logger
    @sincedb = {}
    @sincedb_last_write = 0
    @statcache = {}
    @opts = {
      :sincedb_write_interval => 10,
      :stat_interval => 1,
      :discover_interval => 5,
      :exclude => [],
      :start_new_files_at => :end,
      :delimiter => "\n"
    }.merge(opts)
    if !@opts.include?(:sincedb_path)
      @opts[:sincedb_path] = File.join(ENV["HOME"], ".sincedb") if ENV.include?("HOME")
      @opts[:sincedb_path] = ENV["SINCEDB_PATH"] if ENV.include?("SINCEDB_PATH")
    end
    if !@opts.include?(:sincedb_path)
      raise NoSinceDBPathGiven.new("No HOME or SINCEDB_PATH set in environment. I need one of these set so I can keep track of the files I am following.")
    end
    @watch.exclude(@opts[:exclude])

    _sincedb_open
  end # def initialize

  public
  def logger=(logger)
    @logger = logger
    @watch.logger = logger
  end # def logger=

  public
  def tail(path)
    @watch.watch(path)
  end # def tail

  public
  def subscribe(&block)
    # subscribe(stat_interval = 1, discover_interval = 5, &block)
    @watch.subscribe(@opts[:stat_interval],
                     @opts[:discover_interval]) do |event, path|
      case event
      when :create, :create_initial
        if @files.member?(path)
          @logger.debug? && @logger.debug("#{event} for #{path}: already exists in @files")
          next
        end
        if _open_file(path, event)
          _read_file(path, &block)
        end
      when :modify
        if !@files.member?(path)
          @logger.debug? && @logger.debug(":modify for #{path}, does not exist in @files")
          if _open_file(path, event)
            _read_file(path, &block)
          end
        else
          _read_file(path, &block)
        end
      when :delete
        @logger.debug? && @logger.debug(":delete for #{path}, deleted from @files")
        if @files[path]
          _read_file(path, &block)
          @files[path].close
        end
        @files.delete(path)
        inode = @statcache.delete(path)
        @sincedb.delete(inode)
      else
        @logger.warn("unknown event type #{event} for #{path}")
      end
    end # @watch.subscribe
  end # def subscribe

  public
  def sincedb_record_uid(path, stat)
    inode = @watch.inode(path,stat)
    @statcache[path] = inode
    return inode
  end # def sincedb_record_uid

  private
  def _open_file(path, event)
    @logger.debug? && @logger.debug("_open_file: #{path}: opening")
    begin
      @files[path] = Zlib::GzipReader.open(path)
    rescue
      # don't emit this message too often. if a file that we can't
      # read is changing a lot, we'll try to open it more often,
      # and might be spammy.
      now = Time.now.to_i
      if now - @lastwarn[path] > OPEN_WARN_INTERVAL
        @logger.warn("failed to open #{path}: #{$!}")
        @lastwarn[path] = now
      else
        @logger.debug? && @logger.debug("(warn supressed) failed to open #{path}: #{$!}")
      end
      @files.delete(path)
      return false
    end

    stat = File::Stat.new(path)
    sincedb_record_uid = sincedb_record_uid(path, stat)

    if @sincedb.member?(sincedb_record_uid)
      last_size = @sincedb[sincedb_record_uid]
      @logger.debug? && @logger.debug("#{path}: sincedb last value #{@sincedb[sincedb_record_uid]}, cur size #{stat.size}")
      if last_size <= stat.size
        @logger.debug? && @logger.debug("#{path}: sincedb: seeking to #{last_size}")
        @files[path].read(last_size)
      else
        @logger.debug? && @logger.debug("#{path}: last value size is greater than current value, starting over")
        @sincedb[sincedb_record_uid] = 0
      end
    elsif event == :create_initial && @files[path]
      if @opts[:start_new_files_at] == :beginning
        @logger.debug? && @logger.debug("#{path}: initial create, no sincedb, seeking to beginning of file")
        @files[path].rewind()
        @sincedb[sincedb_record_uid] = 0
      else 
        # seek to end
        size = @files[path].read()
        @logger.debug? && @logger.debug("#{path}: initial create, no sincedb, seeking to end #{size}")
        @sincedb[sincedb_record_uid] = size
      end
    elsif event == :create && @files[path]
      @sincedb[sincedb_record_uid] = 0
    else
      @logger.debug? && @logger.debug("#{path}: staying at position 0, no sincedb")
    end

    return true
  end # def _open_file

  private
  def _read_file(path, &block)
	link_src = path
  	link_src = File.readlink(path) if File.symlink?(path)
  	
    @buffers[path] ||= GzBufferedTokenizer.new(@opts[:delimiter])
    delimiter_byte_size = @opts[:delimiter].bytesize
    changed = false
    loop do
      begin
        data = @files[path].read()
        changed = true
        @buffers[path].extract(data).each do |line|
          @sincedb[@statcache[path]] += (line.bytesize + delimiter_byte_size)
          yield(link_src, line, @sincedb[@statcache[path]])
        end
      rescue Errno::EWOULDBLOCK, Errno::EINTR, EOFError
        break
      end
    end

    if changed
      now = Time.now.to_i
      delta = now - @sincedb_last_write
      if delta >= @opts[:sincedb_write_interval]
        @logger.debug? && @logger.debug("writing sincedb (delta since last write = #{delta})")
        _sincedb_write
        @sincedb_last_write = now
      end
    end
  end # def _read_file

  public
  def sincedb_write(reason=nil)
    @logger.debug? && @logger.debug("caller requested sincedb write (#{reason})")
    _sincedb_write
  end

  private
  def _sincedb_open
    path = @opts[:sincedb_path]
    begin
      db = File.open(path)
    rescue
      #No existing sincedb to load
      @logger.debug? && @logger.debug("_sincedb_open: #{path}: #{$!}")
      return
    end

    @logger.debug? && @logger.debug("_sincedb_open: reading from #{path}")
    db.each do |line|
      ino, dev_major, dev_minor, pos = line.split(" ", 4)
      sincedb_record_uid = [ino, dev_major.to_i, dev_minor.to_i]
      @logger.debug? && @logger.debug("_sincedb_open: setting #{sincedb_record_uid.inspect} to #{pos.to_i}")
      @sincedb[sincedb_record_uid] = pos.to_i
    end
    db.close
  end # def _sincedb_open

  private
  def _sincedb_write
    path = @opts[:sincedb_path]
    IO.write(path, serialize_sincedb, 0)
  end # def _sincedb_write

  public
  def quit
    _sincedb_write
    @watch.quit
  end # def quit

  private
  def serialize_sincedb
    @sincedb.map do |inode, pos|
      [inode, pos].flatten.join(" ")
    end.join("\n") + "\n"
  end
end # class GzTail

# Stream events from zipped files.
#
# By default, each event is assumed to be one line. If you would like
# to join multiple log lines into one event, you'll want to use the
# multiline codec.
#
# Files are followed in a manner similar to `tail -0F`. File rotation
# is detected and handled by this input.
class LogStash::Inputs::GzFile < LogStash::Inputs::Base
  config_name "gzfile"

  # TODO(sissel): This should switch to use the `line` codec by default
  # once file following
  default :codec, "plain"

  # The path(s) to the file(s) to use as an input.
  # You can use globs here, such as `/var/log/*.log`
  # Paths must be absolute and cannot be relative.
  #
  # You may also configure multiple paths. See an example
  # on the <<array,Logstash configuration page>>.
  config :path, :validate => :array, :required => true

  # Exclusions (matched against the filename, not full path). Globs
  # are valid here, too. For example, if you have
  # [source,ruby]
  #     path => "/var/log/*"
  #
  # You might want to exclude gzipped files:
  # [source,ruby]
  #     exclude => "*.log"
  config :exclude, :validate => :array

  # How often (in seconds) we stat files to see if they have been modified.
  # Increasing this interval will decrease the number of system calls we make,
  # but increase the time to detect new log lines.
  config :stat_interval, :validate => :number, :default => 1

  # How often (in seconds) we expand globs to discover new files to watch.
  config :discover_interval, :validate => :number, :default => 15

  # Path of the sincedb database file (keeps track of the current
  # position of monitored log files) that will be written to disk.
  # The default will write sincedb files to some path matching `$HOME/.sincedb*`
  # NOTE: it must be a file path and not a directory path
  config :sincedb_path, :validate => :string

  # How often (in seconds) to write a since database with the current position of
  # monitored log files.
  config :sincedb_write_interval, :validate => :number, :default => 15

  # Choose where Logstash starts initially reading files: at the beginning or
  # at the end. The default behavior treats files like live streams and thus
  # starts at the end. If you have old data you want to import, set this
  # to 'beginning'
  #
  # This option only modifies "first contact" situations where a file is new
  # and not seen before. If a file has already been seen before, this option
  # has no effect.
  config :start_position, :validate => [ "beginning", "end"], :default => "end"

  # set the new line delimiter, defaults to "\n"
  config :delimiter, :validate => :string, :default => "\n"

  public
  def register
    require "addressable/uri"
    require "zlib"
    require "digest/md5"
    @logger.info("Registering file input", :path => @path)
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    @tail_config = {
      :exclude => @exclude,
      :stat_interval => @stat_interval,
      :discover_interval => @discover_interval,
      :sincedb_write_interval => @sincedb_write_interval,
      :delimiter => @delimiter,
      :logger => @logger,
    }

    @path.each do |path|
      if Pathname.new(path).relative?
        raise ArgumentError.new("File paths must be absolute, relative path specified: #{path}")
      end
    end

    if @sincedb_path.nil?
      if ENV["SINCEDB_DIR"].nil? && ENV["HOME"].nil?
        @logger.error("No SINCEDB_DIR or HOME environment variable set, I don't know where " \
                      "to keep track of the files I'm watching. Either set " \
                      "HOME or SINCEDB_DIR in your environment, or set sincedb_path in " \
                      "in your Logstash config for the file input with " \
                      "path '#{@path.inspect}'")
        raise # TODO(sissel): HOW DO I FAIL PROPERLY YO
      end

      #pick SINCEDB_DIR if available, otherwise use HOME
      sincedb_dir = ENV["SINCEDB_DIR"] || ENV["HOME"]

      # Join by ',' to make it easy for folks to know their own sincedb
      # generated path (vs, say, inspecting the @path array)
      @sincedb_path = File.join(sincedb_dir, ".sincedb_" + Digest::MD5.hexdigest(@path.join(",")))

      # Migrate any old .sincedb to the new file (this is for version <=1.1.1 compatibility)
      old_sincedb = File.join(sincedb_dir, ".sincedb")
      if File.exists?(old_sincedb)
        @logger.info("Renaming old ~/.sincedb to new one", :old => old_sincedb,
                     :new => @sincedb_path)
        File.rename(old_sincedb, @sincedb_path)
      end

      @logger.info("No sincedb_path set, generating one based on the file path",
                   :sincedb_path => @sincedb_path, :path => @path)
    end

    if File.directory?(@sincedb_path)
      raise ArgumentError.new("The \"sincedb_path\" argument must point to a file, received a directory: \"#{@sincedb_path}\"")
    end

    @tail_config[:sincedb_path] = @sincedb_path

    if @start_position == "beginning"
      @tail_config[:start_new_files_at] = :beginning
    end
  end # def register

  public
  def run(queue)
    @tail = GzTail.new(@tail_config)
    @tail.logger = @logger
    @path.each { |path| @tail.tail(path) }

    @tail.subscribe do |path, line, pos|
      @logger.debug? && @logger.debug("Received line", :path => path, :text => line, :position => pos)
      @codec.decode(line) do |event|
        event["[@metadata][path]"] = path
        event["host"] = @host if !event.include?("host")
        event["path"] = path if !event.include?("path")
        event["pos"] = pos
        decorate(event)
        queue << event
      end
    end
    finished
  end # def run

  public
  def teardown
    if @tail
      @tail.sincedb_write
      @tail.quit
      @tail = nil
    end
  end # def teardown
end # class LogStash::Inputs::File
