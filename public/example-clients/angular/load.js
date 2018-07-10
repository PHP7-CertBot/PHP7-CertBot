// This actually loads the app, called after the enterpriseauth generated preload.js preloads the app

var loadScripts = [
    // Dependancies
    'bower_components/angular/angular.js',
    'bower_components/angular-messages/angular-messages.js',
    'bower_components/angular-ui-router/release/angular-ui-router.js',
    'bower_components/ngstorage/ngStorage.js',
    // The single page application
    'app.js',
    'app-services/certbot.service.js',
    'home/index.controller.js',
];

// load up all the scripts
for (var i in loadScripts) {
    document.write('<script src="' + loadScripts[i] + '" type="text/javascript"></script>');
}
