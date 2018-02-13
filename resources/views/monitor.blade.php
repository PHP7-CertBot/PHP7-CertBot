<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Expired Certificate Alert</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Raleway:100,600" rel="stylesheet" type="text/css">
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
    </head>
    <body>
        <div class="container">
            <legend>
                <h1>Expired Certificates</h1>
            </legend>

                <div class="jumbotron">
            @foreach ($expired as $cert)
                    <div class="panel panel-default" style="box-shadow: 1px 1px 5px grey;">
                        <div class="table-responsive">
                            <table class="table table-striped table-condensed table-bordered table-hover">
                                <tbody style="font-size: 14px;">
                                    <!--List View-->
                                    <tr><td><b>ID:           </b> {{ $cert->id}}         </td></tr>
                                    <tr><td><b>Name:         </b> {{ $cert->servername}} </td></tr>
                                    <tr><td><b>IP Address:   </b> {{ $cert->ip}}         </td></tr>
                                    <tr><td><b>Port:         </b> {{ $cert->port}}       </td></tr>
                                    <tr><td><b>Issuer:       </b> {{ $cert->issuer}}     </td></tr>
                                    <tr><td><b>Issued At:    </b> {{ $cert->issued_at}}  </td></tr>
                                    <tr><td><b>Expires At:   </b> {{ $cert->expires_at}} </td></tr>
                                    <tr><td><b>Last Scan:    </b> {{ $cert->updated_at}} </td></tr>
                                    <tr><td><b>SubjAltNames: </b> {{ $cert->subjects}}   </td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
            @endforeach
                </div>
        </div>
        <div class="container">
            <legend>
                <h1>Certificates Expiring Soon</h1>
            </legend>

                <div class="jumbotron">
            @foreach ($expiring as $cert)
                    <div class="panel panel-default" style="box-shadow: 1px 1px 5px grey;">
                        <div class="table-responsive">
                            <table class="table table-striped table-condensed table-bordered table-hover">
                                <tbody style="font-size: 14px;">
                                    <!--List View-->
                                    <tr><td><b>ID:           </b> {{ $cert->id}}         </td></tr>
                                    <tr><td><b>Name:         </b> {{ $cert->servername}} </td></tr>
                                    <tr><td><b>IP Address:   </b> {{ $cert->ip}}         </td></tr>
                                    <tr><td><b>Port:         </b> {{ $cert->port}}       </td></tr>
                                    <tr><td><b>Issuer:       </b> {{ $cert->issuer}}     </td></tr>
                                    <tr><td><b>Issued At:    </b> {{ $cert->issued_at}}  </td></tr>
                                    <tr><td><b>Expires At:   </b> {{ $cert->expires_at}} </td></tr>
                                    <tr><td><b>Last Scan:    </b> {{ $cert->updated_at}} </td></tr>
                                    <tr><td><b>SubjAltNames: </b> {{ $cert->subjects}}   </td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
            @endforeach
                </div>
        </div>
    </body>
</html>
