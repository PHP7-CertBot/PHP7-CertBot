<!DOCTYPE html>
<html>
	<head>
		<script type="text/javascript"
		        src="//cdn.rawgit.com/Gavin-Paolucci-Kleinow/ie-truth/master/ie-truth.js"></script>
		<script type="text/javascript"
		        src="//ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
		<script type="text/javascript"
		        src="app.js"></script>
		<style>
			hr{
				size: 1px;
				width: 100%;
			}
		</style>
	</head>
	<body>
		<div id="loading">
			Application Loading...
		</div>
		<div id="badbrowser"
		     style="display: none;">
			This is a javascript only webpage, your browser is not working properly. Use chrome or firefox with javascript enabled.
		</div>
		<div id="login"
		     style="display: none;">
			Login:<br/>
			Username: <input type="text"
			                 id="username"/>
			<br/>
			Password: <input type="password"
			                 id="password"/>
			<br/>
			<button>login</button>
			<pre id="message"></pre>
		</div>
		<div id="app"
		     style="display: none;">
			<div id="title">
				<h2>API TEST PAGE - log level:
					<select id="loglevel">
						<option value="1">1</option>
						<option value="2">2</option>
						<option value="0">Off</option>
					</select> - <button id="clearlog">Clear logs</button>
				</h2>
			</div>
			<div id="content">
				<div id="content-left"
				     style="width: 25%; display: block; float: left;">
					<hr/>
					<div id="logout">
						<button>Logout / Clear Auth Token</button>
					</div>
					<hr/>
					<div id="account">
						Account:
						<select id="type">
							<option value="acme">Acme Client</option>
							<option value="ca">Certificate Authority</option>
						</select>
						<br/>
						<button id="list">
							List
						</button>
						<br/>
						new account name: <input type="text"
						                         id="name"/>
						<br/>
						new account contact email: <input type="text"
						                                  id="contact"/>
						<br/>
						new account zones: <input type="text"
						                          id="zones"/>
						<br/>
						acme ca: <select id="acmecaurl">
							<option value="https://acme-staging.api.letsencrypt.org">LetsEncrypt-Staging</option>
							<option value="https://acme-v01.api.letsencrypt.org">LetsEncrypt-Production</option>
						</select>
						<br/>
						auth type: <select id="authtype">
							<option value="http-01">HTTP (/path/to/www)</option>
							<option value="dns-01">DNS (Cloudflare/Verisign)</option>
						</select>
						<br/>
						auth provider: <input type="text"
						                      id="authprovider"/>
						<br/>
						auth user: <input type="text"
						                  id="authuser"/>
						<br/>
						auth pass: <input type="text"
						                  id="authpass"/>
						<br/>
						<button id="new">New</button>
						<br/>
						account id: <input type="text"
						                   id="id"/>
						<br/>
						<button id="update">Update local accouint</button>
						<br/>
						<button id="updatereg">Update account with CA</button>
						<br/>
					</div>
					<hr/>
					<div id="certificate">
						Certificates:<br/>
						<button id="list">List</button>
						<br/>
						cert name: <input type="text"
						                  id="name"
						                  size="30"/>
						<br/>
						cert subjects:
						<input type="text"
						       id="subjects"
						       size="30"/>
						<br/>
						type:
						<select id="type">
							<option value="server">Server</option>
							<option value="user">User</option>
							<option value="ca">CA</option>
						</select>
						<br/>
						<button id="new">New</button>
						<br/>
						cert id: <input type="text"
						                id="id"/>
						<br/>
						<button id="generaterequest">Generate CSR</button>
						<br/>
						<button id="sign">Sign CSR</button>
						<br/>
						<button id="renew">Renew Certificate</button>
						<br/>
					</div>
					<hr/>
					<div id="debug">
						Debug:<br/>
						<button id="debug">Debug</button>
						<br/>
					</div>
					<hr/>
				</div>
				<div id="content-right"
				     style="width: 75%; display: block; float: left;">
					<hr/>
					<pre id="response">LOG MESSAGES:</pre>
				</div>
			</div>
		</div>
	</body>
</html>
