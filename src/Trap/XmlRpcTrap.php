<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * XML-RPC endpoint trap.
 *
 * Responds to /xmlrpc.php requests with plausible WordPress XML-RPC
 * responses for common methods (system.listMethods, pingback.ping, etc.).
 */
class XmlRpcTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'xmlrpc';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $response->setContentType('text/xml; charset=UTF-8');
        $response->setHeader('Server', 'Apache/2.4.58');

        if ($request->isGet()) {
            $response->setStatusCode(200);
            $response->setBody($this->getServerInfo());
            return $response;
        }

        // POST: parse the XML-RPC method call
        $body = $request->getBody();
        $methodName = $this->extractMethodName($body);

        $responseXml = match ($methodName) {
            'system.listMethods'      => $this->listMethods(),
            'system.getCapabilities'  => $this->getCapabilities(),
            'pingback.ping'           => $this->pingbackPing(),
            'wp.getUsersBlogs'        => $this->getUsersBlogsFault(),
            'wp.getOptions'           => $this->getOptionsFault(),
            'wp.getUsers'             => $this->getUsersBlogsFault(),
            'metaWeblog.getUsersBlogs' => $this->getUsersBlogsFault(),
            'blogger.getUsersBlogs'   => $this->getUsersBlogsFault(),
            'demo.sayHello'           => $this->demoSayHello(),
            default                   => $this->unknownMethod($methodName),
        };

        $response->setStatusCode(200);
        $response->setBody($responseXml);

        return $response;
    }

    /**
     * Extract the method name from an XML-RPC request body.
     */
    private function extractMethodName(string $body): string
    {
        if (preg_match('#<methodName>(.+?)</methodName>#s', $body, $matches)) {
            return trim($matches[1]);
        }

        return '';
    }

    /**
     * GET response: XML-RPC server info page.
     */
    private function getServerInfo(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value><string>XML-RPC server accepts POST requests only.</string></value>
    </param>
  </params>
</methodResponse>
XML;
    }

    /**
     * system.listMethods response with WordPress methods.
     */
    private function listMethods(): string
    {
        $methods = [
            'system.listMethods',
            'system.getCapabilities',
            'system.multicall',
            'demo.sayHello',
            'demo.addTwoNumbers',
            'pingback.ping',
            'pingback.extensions.getPingbacks',
            'wp.getUsersBlogs',
            'wp.newPost',
            'wp.editPost',
            'wp.deletePost',
            'wp.getPost',
            'wp.getPosts',
            'wp.newTerm',
            'wp.editTerm',
            'wp.deleteTerm',
            'wp.getTerm',
            'wp.getTerms',
            'wp.getTaxonomy',
            'wp.getTaxonomies',
            'wp.getUser',
            'wp.getUsers',
            'wp.getProfile',
            'wp.editProfile',
            'wp.getPage',
            'wp.getPages',
            'wp.newPage',
            'wp.deletePage',
            'wp.editPage',
            'wp.getPageList',
            'wp.getAuthors',
            'wp.getCategories',
            'wp.getTags',
            'wp.newCategory',
            'wp.deleteCategory',
            'wp.suggestCategories',
            'wp.uploadFile',
            'wp.deleteFile',
            'wp.getCommentCount',
            'wp.getPostStatusList',
            'wp.getPageStatusList',
            'wp.getPageTemplates',
            'wp.getOptions',
            'wp.setOptions',
            'wp.getComment',
            'wp.getComments',
            'wp.deleteComment',
            'wp.editComment',
            'wp.newComment',
            'wp.getCommentStatusList',
            'wp.getMediaItem',
            'wp.getMediaLibrary',
            'wp.getPostFormats',
            'wp.getPostType',
            'wp.getPostTypes',
            'wp.getRevisions',
            'wp.restoreRevision',
            'blogger.getUsersBlogs',
            'blogger.getUserInfo',
            'blogger.getPost',
            'blogger.getRecentPosts',
            'blogger.newPost',
            'blogger.editPost',
            'blogger.deletePost',
            'metaWeblog.newPost',
            'metaWeblog.editPost',
            'metaWeblog.getPost',
            'metaWeblog.getRecentPosts',
            'metaWeblog.getCategories',
            'metaWeblog.newMediaObject',
            'metaWeblog.deletePost',
            'metaWeblog.getUsersBlogs',
            'mt.getCategoryList',
            'mt.getRecentPostTitles',
            'mt.getPostCategories',
            'mt.setPostCategories',
            'mt.supportedMethods',
            'mt.supportedTextFilters',
            'mt.getTrackbackPings',
            'mt.publishPost',
        ];

        $values = '';
        foreach ($methods as $method) {
            $values .= "        <value><string>" . htmlspecialchars($method, ENT_XML1) . "</string></value>\n";
        }

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
{$values}          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>
XML;
    }

    /**
     * system.getCapabilities response.
     */
    private function getCapabilities(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>xmlrpc</name>
            <value><struct>
              <member><name>specUrl</name><value><string>http://www.xmlrpc.com/spec</string></value></member>
              <member><name>specVersion</name><value><int>1</int></value></member>
            </struct></value>
          </member>
          <member>
            <name>system.multicall</name>
            <value><struct>
              <member><name>specUrl</name><value><string>http://www.xmlrpc.com/discuss/msgReader$1208</string></value></member>
              <member><name>specVersion</name><value><int>1</int></value></member>
            </struct></value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodResponse>
XML;
    }

    /**
     * pingback.ping: fake success response.
     */
    private function pingbackPing(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value><string>Pingback from your site to our site was registered. Keep the web talking! :-)</string></value>
    </param>
  </params>
</methodResponse>
XML;
    }

    /**
     * wp.getUsersBlogs / authentication-required methods: return fault (bad credentials).
     */
    private function getUsersBlogsFault(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
XML;
    }

    /**
     * wp.getOptions fault for unauthenticated access.
     */
    private function getOptionsFault(): string
    {
        return $this->getUsersBlogsFault();
    }

    /**
     * demo.sayHello response.
     */
    private function demoSayHello(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value><string>Hello!</string></value>
    </param>
  </params>
</methodResponse>
XML;
    }

    /**
     * Unknown method fault.
     */
    private function unknownMethod(string $methodName): string
    {
        $escaped = htmlspecialchars($methodName, ENT_XML1);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32601</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>server error. requested method {$escaped} does not exist.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
XML;
    }
}
