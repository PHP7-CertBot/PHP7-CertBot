$(document).ready(function(){

	// Hide the loading message
	$("#loading").hide();

	// Check for IE dumbness
	var IE = IeVersion();
	if ( IE.IsIE ) {
		$("#badbrowser").show();
		alert('I do not support the internet explorer, it breaks too much javascript');
		window.stop();
	}

	// Try to authenticate to the API and get our JWT
	function authenticate(){
		jwt = null; // flush out our jwt.
		var url = '/api/authenticate';
		var method = 'POST';
		var data = {
			username: $("#login > input#username").val(),
			password: $("#login > input#password").val(),
		};
		var success = function(response){
			jwt = response.token;
			pagelog(0,'login successful, got jwt token: ' + jwt);
			$("#login").hide();
			$("#app").show();
		}
		var failure = function(error) {
			pagelog(0,'login failed with error: ' + error.responseText );
			var message = JSON.parse(error.responseText);
			console.log(message);
			$("#login > pre#message").append(message.message);
			$("#app").hide();
			$("#login").show();
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	}

	// variable for our authentication token for the api
	var jwt = null;
	// Attempt to automagically authenticate with client TLS certificate
	pagelog(2,'attempting automagic login with certificate');
	$("#login > pre#message").append('attempting automatic certificate login\n');
	authenticate();

	// login button action
	$("#login > button").click(function(){
		$("#login > pre#message").html('');
		pagelog(2,'login button clicked');
		authenticate();
	});

	// page logging information and level for debug purposes
	var loglevel = 1;
	$("#loglevel").change(function(newlevel){
		pagelog(0,'changing loglevel from ' + loglevel + ' to ' + $("#loglevel").val() );
		loglevel = $("#loglevel").val();
	});

	// Clear our log messages pre
	$("#clearlog").click(function(newlevel){
		$("#response").html('LOG MESSAGES:\n');
	});

	// dumb wrapper for the page output append
	function pagelog(level, message) {
		if(level <= loglevel) {
			$("#response").append('\n' + message);
		}
	}

	// dumb wrapper for api calls because im lazy and bad at javascript
	function apicall(url, method, data, goodcall, badcall) {
		// if we have a JWT set, send it with the request
		if(jwt != null) {
			url = url + '?token=' + jwt;
		}
		pagelog(1,'SENT:' + method + ' ' + url + ' DATA: ' + JSON.stringify(data) );
		// call the ajax and wait for it to complete
		var ajaxCall = $.ajax({
			url: url,
			method: method,
			data: data,
			success: function(data) {
				pagelog(2,'RECV: ' + JSON.stringify(data));
				// this is some optional code to capture updated auth tokens as we make calls
				var responseHeaders = ajaxCall.getAllResponseHeaders();
				var regex = /authorization: Bearer ([a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*)/;
				if(responseHeaders.match(regex)) {
					jwt = responseHeaders.match(regex)[1];
					pagelog(2,'api auth token updated: ' + jwt);
				}else{
					pagelog(2,'api auth token not updated after this call');
				}
				// invoke the success callback function
				goodcall(data);
			},
			error: function(error, errorThrown) {
				pagelog(2,'ERROR: ' + JSON.stringify(error) + 'error: ' + JSON.stringify(errorThrown));
				// invoke the failure callback function
				badcall(error);
			}
		});
	}

	// logout button action
	$("#logout > button").click(function(){
		pagelog(2,'logout button clicked');
		jwt = null;
		pagelog(0,'logged out. jwt = ' + jwt);
		$("#app").hide();
		$("#login").show();
	});

	$("#debug > button#debug").click(function(){
		pagelog(2,'debug button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/debug';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'got: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	// new account button action
	$("#account > button#new").click(function(){
		pagelog(2,'newaccount button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account';
		var method = 'POST';
		var data = {
			name: $("#account > input#name").val(),
			contact: $("#account > input#contact").val(),
			zones: $("#account > input#zones").val(),
			acmecaurl: $("#account > #acmecaurl").val(),
			acmelicense: 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf',
			authtype: $("#account > #authtype").val(),
			authprovider: $("#account > input#authprovider").val(),
			authuser: $("#account > input#authuser").val(),
			authpass: $("#account > input#authpass").val(),
		};
		var success = function(response){
			pagelog(0,'success, got response: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'failed with error: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#account > button#update").click(function(){
		pagelog(2,'updataccount button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' + $("#account > input#id").val();
		var method = 'PUT';
		var data = {
			name: $("#account > input#name").val(),
			contact: $("#account > input#contact").val(),
			zones: $("#account > input#zones").val(),
			acmecaurl: $("#account > #acmecaurl").val(),
			acmelicense: 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf',
			authtype: $("#account > #authtype").val(),
			authprovider: $("#account > input#authprovider").val(),
			authuser: $("#account > input#authuser").val(),
			authpass: $("#account > input#authpass").val(),
		};
		var success = function(response){
			pagelog(0,'success, got response: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'failed with error: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#account > button#updatereg").click(function(){
		pagelog(2,'updatereg clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/updatereg';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'got account: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error getting account: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#account > button#list").click(function(){
		pagelog(2,'listaccounts button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'got account: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error getting account: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#list").click(function(){
		pagelog(2,'listcerts button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'certificates for account: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error finding certificates: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#new").click(function(){
		pagelog(2,'newcert button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate';
		var method = 'POST';
		var data = {
					name: $("#certificate > input#name").val(),
					subjects: JSON.parse( $("#certificate > input#subjects").val() )
				};
		var success = function(response){
			pagelog(0,'success, got response: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'failed with error: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#generatekeys").click(function(){
		pagelog(2,'gen keys button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate/' + $("#certificate > input#id").val() + '/generatekeys';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'key pair generation: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error generating keys: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#generaterequest").click(function(){
		pagelog(2,'csr button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate/' + $("#certificate > input#id").val() + '/generaterequest';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'certificate request generation: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error generating csr: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#sign").click(function(){
		pagelog(2,'sign button clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate/' + $("#certificate > input#id").val() + '/sign';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'certificates sign: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error finding certificates: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

	$("#certificate > button#renew").click(function(){
		pagelog(2,'renew clicked');
		var url = '/api/' +  $("#account > select#type").val() + '/account/' +  $("#account > input#id").val() + '/certificate/' + $("#certificate > input#id").val() + '/renew';
		var method = 'GET';
		var data = {};
		var success = function(response){
			pagelog(0,'certificates renew: ' + JSON.stringify(response, null, 4) );
		}
		var failure = function(error) {
			pagelog(0,'error finding certificates: ' + error.responseText );
		}
		// run the api call specified and wait for its response
		apicall(url, method, data, success, failure)
	});

});
