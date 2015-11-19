<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace fkooman\Rest\Plugin\Authentication\Form;

use fkooman\Http\SessionInterface;
use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use fkooman\Tpl\TemplateManagerInterface;
use fkooman\Http\Response;
use fkooman\Http\RedirectResponse;
use InvalidArgumentException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Http\Exception\BadRequestException;

class FormAuthentication implements AuthenticationPluginInterface
{
    /** @var callable */
    private $retrieveHash;

    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \fkooman\Http\SessionInterface */
    private $session;

    /** @var array */
    private $authParams;

    public function __construct($retrieveHash, TemplateManagerInterface $templateManager, array $authParams = array())
    {
        if (!is_callable($retrieveHash)) {
            throw new InvalidArgumentException('argument must be callable');
        }
        $this->retrieveHash = $retrieveHash;

        $this->templateManager = $templateManager;

        $this->session = null;

        if (!array_key_exists('realm', $authParams)) {
            $authParams['realm'] = 'Protected Resource';
        }
        $this->authParams = $authParams;
    }

    public function setSession(SessionInterface $session)
    {
        $this->session = $session;
    }

    public function isAuthenticated(Request $request)
    {
        if (null !== $this->session->get('userName')) {
            return new FormUserInfo($this->session->get('userName'));
        }

        return false;
    }

    public function init(Service $service)
    {
        if (null === $this->session) {
            // XXX idealy we want to get rid of this...
            $this->session = new Session('Form');
        }

        $service->post(
            '/_auth/form/verify',
            function (Request $request) {
                $httpReferrer = $request->getHeader('Referer');
                if (null === $httpReferrer) {
                    throw new BadRequestException('Referrer header not sent');
                }

                // delete possibly stale auth session
                $this->session->delete('userName');

                // validate password
                $userName = $request->getPostParameter('userName');
                $userPass = $request->getPostParameter('userPass');

                $passHash = call_user_func($this->retrieveHash, $userName);
                if (false === $passHash || !password_verify($userPass, $passHash)) {
                    // XXX: use proper query parameter appending, could also be '&'!
                    return new RedirectResponse($httpReferrer . '?_auth_form_verify=invalid_credentials', 302);
                }

                $this->session->set('userName', $userName);
                return new RedirectResponse($httpReferrer, 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );

        $service->post(
            '/_auth/form/logout',
            function (Request $request) {
                $this->session->destroy();
                $redirectTo = self::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getPostParameter('redirect_to'));

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );
    }

    public function requestAuthentication(Request $request)
    {
        $response = new Response(200);  // XXX use 401 instead?
        $response->setHeader('X-Frame-Options', 'DENY');
        $response->setHeader('Content-Security-Policy', "default-src 'self'");
        $response->setBody(
            $this->templateManager->render(
                'formAuth',
                array(
                    'login_hint' => $request->getUrl()->getQueryParameter('login_hint'),
                )
            )
        );

        return $response;
    }

    private static function validateRedirectTo($rootUrl, $redirectTo)
    {
        // no redirectTo specified
        if (null === $redirectTo) {
            $redirectTo = $rootUrl;
        }

        // if redirectTo starts with a '/' append it to rootUrl
        if (0 === strpos($redirectTo, '/')) {
            $redirectTo = $rootUrl.substr($redirectTo, 1);
        }

        if (false === filter_var($redirectTo, FILTER_VALIDATE_URL)) {
            throw new BadRequestException(sprintf('invalid redirect_to URL "%s"', $redirectTo));
        }

        // URL needs to start with absRoot
        if (0 !== strpos($redirectTo, $rootUrl)) {
            throw new BadRequestException('redirect_to needs to point to a URL relative to the application root');
        }

        return $redirectTo;
    }
}
