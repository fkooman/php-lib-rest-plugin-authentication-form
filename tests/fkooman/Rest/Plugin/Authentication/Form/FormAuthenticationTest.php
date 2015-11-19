<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
namespace fkooman\Rest\Plugin\Authentication\Form;

require_once __DIR__.'/Test/TestTemplateManager.php';
require_once __DIR__.'/Test/TestSession.php';

use PHPUnit_Framework_TestCase;
use fkooman\Rest\Plugin\Authentication\Form\Test\TestTemplateManager;
use fkooman\Rest\Plugin\Authentication\Form\Test\TestSession;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\AuthenticationPlugin;

class FormAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testAuth()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $testSession->set('userName', 'foo');
        $formAuth->setSession($testSession);
        $this->assertEquals('foo', $formAuth->isAuthenticated($request)->getUserId());
    }

    public function testAuthNotAuthenticated()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'login_hint=foo',
                'REQUEST_URI' => '/?login_hint=foo',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $formAuth->setSession($testSession);
        $this->assertFalse($formAuth->isAuthenticated($request));
        $response = $formAuth->requestAuthentication($request);
        $this->assertSame(
            array(
                'HTTP/1.1 200 OK',
                'Content-Type: text/html;charset=UTF-8',
                'X-Frame-Options: DENY',
                "Content-Security-Policy: default-src 'self'",
                'Content-Length: 51',
                '',
                '{"formAuth":{"login_hint":"foo","auth_error":null}}',
            ),
            $response->toArray()
        );
        $this->assertNull($testSession->get('userName'));
    }

    public function testVerifyCorrectCredentials()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'HTTP_ACCEPT' => 'text/html',
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_auth/form/verify',
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/form/verify',
                'REQUEST_METHOD' => 'POST',
            ),
            array(
                'userName' => 'foo',
                'userPass' => 'bar',
            )
        );
        $service = new Service();
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $formAuth->setSession($testSession);
        $ap = new AuthenticationPlugin();
        $ap->register($formAuth, 'form');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
        $this->assertSame('foo', $testSession->get('userName'));
    }

    public function testVerifyWrongUser()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'HTTP_ACCEPT' => 'text/html',
                'REQUEST_URI' => '/_auth/form/verify',
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/form/verify',
                'REQUEST_METHOD' => 'POST',
            ),
            array(
                'userName' => 'fooz',
                'userPass' => 'bar',
            )
        );
        $service = new Service();
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $formAuth->setSession($testSession);
        $ap = new AuthenticationPlugin();
        $ap->register($formAuth, 'form');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
        $this->assertSame('invalid_credentials', $testSession->get('authError'));
        $response = $formAuth->requestAuthentication($request);
        $this->assertSame(
            array(
                'HTTP/1.1 200 OK',
                'Content-Type: text/html;charset=UTF-8',
                'X-Frame-Options: DENY',
                "Content-Security-Policy: default-src 'self'",
                'Content-Length: 67',
                '',
                '{"formAuth":{"login_hint":null,"auth_error":"invalid_credentials"}}',

            ),
            $response->toArray()
        );
        $this->assertNull($testSession->get('userName'));
    }

    public function testVerifyWrongPass()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'HTTP_ACCEPT' => 'text/html',
                'REQUEST_URI' => '/_auth/form/verify',
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/form/verify',
                'REQUEST_METHOD' => 'POST',
            ),
            array(
                'userName' => 'foo',
                'userPass' => 'baz',
            )
        );
        $service = new Service();
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $formAuth->setSession($testSession);
        $ap = new AuthenticationPlugin();
        $ap->register($formAuth, 'form');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
        $this->assertSame('invalid_credentials', $testSession->get('authError'));
    }

    public function testLogout()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'HTTP_ACCEPT' => 'text/html',
                'REQUEST_URI' => '/_auth/form/logout',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_auth/form/logout',
                'REQUEST_METHOD' => 'POST',
                'HTTP_REFERER' => 'http://www.example.org/',
            )
        );
        $service = new Service();
        $formAuth = $this->getFormAuth();
        $testSession = new TestSession();
        $testSession->set('userName', 'foo');
        $formAuth->setSession($testSession);
        $ap = new AuthenticationPlugin();
        $ap->register($formAuth, 'form');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
        $this->assertNull($testSession->get('userName'));
    }

    private function getFormAuth()
    {
        $formAuth = new FormAuthentication(
            function ($userId) {
                // foo:bar
                return 'foo' === $userId ? '$2y$10$L/pq7XXpV54.iAk2EE74deR4yR54yEaZb92.gxH2jDEAZkpcWbhiW' : false;
            },
            new TestTemplateManager()
        );

        return $formAuth;
    }
}
