

module ApJavaCrypto
  module BenchmarkUtils
   
    def self.mark_start()
    java.lang.System.nanoTime()
    end

    def self.time_taken(start, output = :mili)
      res = java.lang.System.nanoTime() - start
      case output
      when :mili
        #taken = java.util.concurrent.TimeUnit::MILLISECONDS.convert(res, java.util.concurrent.TimeUnit::NANOSECONDS)
        taken = res / 1_000_000.0
        {time: {taken: taken, unit: :miliseconds}}
      else
        {time: {taken: res, unit: :nanoseconds}}
      end
    end

  end
end
