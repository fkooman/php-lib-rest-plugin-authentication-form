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

use PHPUnit_Framework_TestCase;
use fkooman\Rest\Plugin\Authentication\Form\Test\TestTemplateManager;
use fkooman\Http\Request;
use fkooman\Rest\Service;

class FormAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testNotAuthenticated()
    {
        $tpl = new TestTemplateManager();
        $formAuth = new FormAuthentication(
            function ($userId) {
                return '$2y$10$L/pq7XXpV54.iAk2EE74deR4yR54yEaZb92.gxH2jDEAZkpcWbhiW'; // bar   
            },
            $tpl
        );

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('get')->will($this->returnValue(null));
        $formAuth->setSession($sessionStub);
        $formAuth->init(new Service());

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
        $response = $formAuth->execute($request, array());
        $this->assertSame(
            array(
                'HTTP/1.1 200 OK',
                'Content-Type: text/html;charset=UTF-8',
                'X-Frame-Options: DENY',
                "Content-Security-Policy: default-src 'self'",
                'Content-Length: 33',
                '',
                '{"formAuth":{"login_hint":"foo"}}',
            ),
            $response->toArray()
        );
    }

    public function testAuthenticationAttempt()
    {
        $tpl = new TestTemplateManager();
        $formAuth = new FormAuthentication(
            function ($userId) {
                return '$2y$10$L/pq7XXpV54.iAk2EE74deR4yR54yEaZb92.gxH2jDEAZkpcWbhiW'; // bar
            },
            $tpl
        );
        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('get')->will($this->returnValue(null));
        $formAuth->setSession($sessionStub);

        $service = new Service();
        $formAuth->init($service);

        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_auth/form/verify',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_auth/form/verify',
                'REQUEST_METHOD' => 'POST',
                'HTTP_REFERER' => 'https://app.example.org/',
            ),
            array(
                'userName' => 'foo',
                'userPass' => 'bar',
            )
        );

        $response = $service->run($request);

        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: https://app.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
    }

    public function testLogout()
    {
        $tpl = new TestTemplateManager();
        $formAuth = new FormAuthentication(
            function ($userId) {
                return '$2y$10$L/pq7XXpV54.iAk2EE74deR4yR54yEaZb92.gxH2jDEAZkpcWbhiW'; // bar
            },
            $tpl
        );
        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('get')->will($this->returnValue('foo'));
        $formAuth->setSession($sessionStub);

        $service = new Service();
        $formAuth->init($service);

        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_auth/form/logout',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_auth/form/logout',
                'REQUEST_METHOD' => 'POST',
                'HTTP_REFERER' => 'https://app.example.org/',
            )
        );

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
    }
}
