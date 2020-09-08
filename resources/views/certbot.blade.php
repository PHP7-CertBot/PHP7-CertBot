<!DOCTYPE html>
<html>
    <head>
        <title>PHP7-CertBot</title>

        <link href="https://fonts.googleapis.com/css?family=Lato:100" rel="stylesheet" type="text/css">

        <style>
            html, body {
                height: 100%;
            }

            body {
                margin: 0;
                padding: 0;
                width: 100%;
                display: table;
                font-weight: 100;
                font-family: 'Lato';
            }

            .band {
                position: absolute;
                top: 0;
                right: 0;
                border: 0;
            }

            .container {
                text-align: center;
                display: table-cell;
                vertical-align: middle;
            }

            .content {
                text-align: center;
                display: inline-block;
            }

            .title {
                font-size: 96px;
            }

            .documentation {
                text-align: left;
                font-size: 32px;
            }
            .documentation a {
                text-decoration: none;
                color: blue;
            }
            .documentation ul {
                margin: 0px;
            }

            .footer {
                position: absolute;
                width: 100%;
                left: 0px;
                bottom: 0px;
            }

            .banner {
                display: block;
                text-align: center;
            }
            .banner img {
                height: 50px;
            }
        </style>
    </head>
    <body>
        <div class="band">
            <a href="https://github.com/PHP7-CertBot/PHP7-CertBot">
            <img src="images/githubforkmegreen.png">
            </a>
        </div>
        <div class="container">
            <div class="content">
                <div class="title">PHP7-CertBot</div>
                <div class="badges">
                    <br>
                    <img src="https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/build.png?b=master">
                    <img src="https://styleci.io/repos/62511938/shield?branch=master">
                    <img src="https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/coverage.png?b=master">
                    <img src="https://scrutinizer-ci.com/g/PHP7-CertBot/PHP7-CertBot/badges/quality-score.png?b=master">
                    <br>
                    <br>
                </div>
                <div class="documentation">
                    <ul>
                        <li>
                            <a href="api/documentation/">API Documentation</a>
                        </li>
                        <li>
                            <a href="monitor/">Certificate Expiration Monitor</a>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="footer">
            <div class="banner">
                <img src="images/letsencrypt.png">
                <img src="images/gplv3.png">
                <img src="images/laravel.png">
                <img src="images/jwtio.png">
                <img src="images/phpseclib.png">
                <img src="images/swagger.png">
                <img src="images/nginx.png">
                <img src="images/php7.png">
                <img src="images/mysql.png">
            </div>
        </div>
    </body>
</html>
