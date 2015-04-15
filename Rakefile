require "rexml/document"
require "rexml/xpath"
include REXML

XMLFILE = "draft-schaad-cose.xml"
CDDLFILE = "cose-extracted.cddl"

task :verify => [CDDLFILE, XMLFILE] do |t|
  doc = Document.new(File.read(XMLFILE))
  XPath.each(doc, "//artwork[@type='CBORdiag']/text()") do |snip|
    IO.popen("diag2cbor.rb | cddl #{CDDLFILE} v -", 'r+') do |io|
      io.write snip.to_s.gsub("nil", "null").gsub(/\n\s*/, "")
      io.close_write
      p io.read
    end
  end
end

task :gen => CDDLFILE  do |t|
  sh "cddl #{t.source} g"
end

file CDDLFILE => [XMLFILE] do |t|
  doc = Document.new(File.read(t.source))
  File.open(t.name, "w") do |f|
    f.puts XPath.match(doc, "//artwork[@type='CDDL']/text()").to_a.join
  end
end

rule ".xml" => ".md" do |t|
  sh "make #{t.name}"
end
