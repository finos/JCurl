class Jcurl < Formula
  desc "JSON-aware curl in Java"
  homepage "https://github.com/symphonyoss/JCurl"
  version "0.9.11"
  url "https://github.com/symphonyoss/JCurl/releases/download/jcurl-#{version}/jcurl.jar", :nounzip => true
  sha256 "b4bb73bee7a29b28e18ea7d16f8ed4d6d86222e92da8771e9ff25ac3234acd1c"

  def install
  	prefix.install "jcurl.jar"
  	(bin/"jcurl").write <<~EOS
      #!/bin/sh
      
      java -jar #{prefix}/jcurl.jar
    EOS
  end
end
