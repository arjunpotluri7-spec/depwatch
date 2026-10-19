package io.github.arjunpotluri7spec.depwatch.input;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A hardened XML reader that builds a small element tree with line numbers.
 *
 * <p>XXE defense: DOCTYPE declarations are rejected outright ({@code disallow-doctype-decl}), so no
 * internal or external entity can be declared. As defense in depth, external general and parameter
 * entities, external DTD loading and XInclude are also disabled, JAXP secure processing is on,
 * {@code ACCESS_EXTERNAL_DTD} / {@code ACCESS_EXTERNAL_SCHEMA} are empty, and the entity resolver
 * refuses every lookup. A file with a DOCTYPE is rejected with a clear error rather than parsed.
 * Element count, depth and text size are also bounded.
 */
public final class SecureXml {

  static final int MAX_ELEMENTS = 200_000;
  static final int MAX_DEPTH = 64;
  static final int MAX_TEXT = 64 * 1024;

  private SecureXml() {}

  /** An element with its trimmed text and the line where its start tag ends. */
  public static final class Element {
    private final String name;
    private final int line;
    private final StringBuilder text = new StringBuilder();
    private final List<Element> children = new ArrayList<>();

    Element(String name, int line) {
      this.name = name;
      this.line = line;
    }

    public String name() {
      return name;
    }

    public int line() {
      return line;
    }

    public String text() {
      return text.toString().strip();
    }

    public List<Element> children() {
      return children;
    }

    public Optional<Element> child(String childName) {
      return children.stream().filter(c -> c.name.equals(childName)).findFirst();
    }

    public List<Element> children(String childName) {
      return children.stream().filter(c -> c.name.equals(childName)).toList();
    }

    /** Text of a direct child, or empty if the child is absent or blank. */
    public Optional<String> childText(String childName) {
      return child(childName).map(Element::text).filter(s -> !s.isEmpty());
    }
  }

  /**
   * Parses an XML document.
   *
   * @throws DepwatchException naming the file, line and problem; a DOCTYPE is reported as an XXE
   *     protection rejection
   */
  public static Element parse(byte[] data, String fileName) {
    Handler handler = new Handler();
    try {
      SAXParser parser = factory().newSAXParser();
      parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      XMLReader reader = parser.getXMLReader();
      reader.setEntityResolver(
          (publicId, systemId) -> {
            throw new SAXException("external entity lookups are disabled");
          });
      reader.setContentHandler(handler);
      reader.setErrorHandler(handler);
      reader.setDTDHandler(handler);
      reader.parse(new InputSource(new ByteArrayInputStream(data)));
    } catch (SAXParseException e) {
      throw new DepwatchException(describe(fileName, e), e);
    } catch (SAXException e) {
      throw new DepwatchException(fileName + ": XML rejected (" + e.getMessage() + ")", e);
    } catch (ParserConfigurationException | IOException e) {
      throw new DepwatchException(fileName + ": cannot parse XML (" + e.getMessage() + ")", e);
    }
    if (handler.root == null) {
      throw new DepwatchException(fileName + ": XML document has no root element");
    }
    return handler.root;
  }

  static SAXParserFactory factory() throws ParserConfigurationException {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.setNamespaceAware(true);
    f.setValidating(false);
    f.setXIncludeAware(false);
    try {
      f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      f.setFeature("http://xml.org/sax/features/external-general-entities", false);
      f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    } catch (SAXException e) {
      // Refuse to run with a parser that cannot be hardened.
      throw new ParserConfigurationException("XML parser cannot be hardened: " + e.getMessage());
    }
    return f;
  }

  private static String describe(String fileName, SAXParseException e) {
    String where = e.getLineNumber() > 0 ? fileName + ":" + e.getLineNumber() : fileName;
    String msg = String.valueOf(e.getMessage());
    if (msg.contains("DOCTYPE") || msg.contains("disallow-doctype-decl")) {
      return where
          + ": DOCTYPE declarations are not allowed (XXE protection); file rejected without"
          + " resolving any entity";
    }
    return where + ": invalid XML (" + msg + ")";
  }

  private static final class Handler extends DefaultHandler {
    private final Deque<Element> stack = new ArrayDeque<>();
    private Locator locator;
    private Element root;
    private int count;

    @Override
    public void setDocumentLocator(Locator locator) {
      this.locator = locator;
    }

    @Override
    public InputSource resolveEntity(String publicId, String systemId) throws SAXException {
      throw new SAXException("external entity lookups are disabled");
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes)
        throws SAXException {
      if (++count > MAX_ELEMENTS) {
        throw new SAXException("more than " + MAX_ELEMENTS + " elements");
      }
      if (stack.size() >= MAX_DEPTH) {
        throw new SAXException("elements nested deeper than " + MAX_DEPTH);
      }
      String name = localName == null || localName.isEmpty() ? qName : localName;
      Element e = new Element(name, locator == null ? 0 : locator.getLineNumber());
      if (stack.isEmpty()) {
        root = e;
      } else {
        stack.peek().children.add(e);
      }
      stack.push(e);
    }

    @Override
    public void endElement(String uri, String localName, String qName) {
      stack.pop();
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
      Element top = stack.peek();
      if (top == null) {
        return;
      }
      if (top.text.length() + length > MAX_TEXT) {
        throw new SAXException("element text longer than " + MAX_TEXT + " characters");
      }
      top.text.append(ch, start, length);
    }

    @Override
    public void warning(SAXParseException e) {
      // Warnings are not actionable for the user here.
    }

    @Override
    public void error(SAXParseException e) throws SAXException {
      throw e;
    }

    @Override
    public void fatalError(SAXParseException e) throws SAXException {
      throw e;
    }
  }
}
