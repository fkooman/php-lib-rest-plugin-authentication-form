<?php

use fkooman\Tpl\TemplateManagerInterface;

class SimpleTpl implements TemplateManagerInterface
{
    public function setDefault(array $templateVariables)
    {
    }

    public function render($templateName, array $templateVariables)
    {
        if ('indexPage' === $templateName) {
            return '<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Index</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Index</h2>
                            <p>Visit the <a href="welcomePage">Welcome Page</a>, you need to be logged in.</p>
                    </body>
                </html>';
        };

        if ('formAuth' === $templateName) {
            return sprintf('<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Sign In</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Sign In</h2>
                            <p>Please sign in with your username and password.</p>
                            <form method="post" action="_auth/form/verify">
                                <input type="text" name="userName" placeholder="Username" value="%s" required>
                                <input type="password" name="userPass" placeholder="Password" required>
                                <button type="submit">Sign in</button>
                            </form>
                    </body>
                </html>',
                $templateVariables['login_hint']
            );
        }

        if ('welcomePage' === $templateName) {
            return sprintf('<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Welcome</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Welcome</h2>
                            <p>Hello %s!</p>
                            <form method="post" action="_auth/form/logout?redirect_to=/">
                                <input type="submit" value="Logout">
                            </form>
                    </body>
                </html>',
                $templateVariables['user_id']
            );
        }

        return '';
    }
}
