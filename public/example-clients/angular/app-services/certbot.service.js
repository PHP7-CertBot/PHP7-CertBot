(function () {
    'use strict';

    angular
        .module('app')
        .factory('CertbotService', Service);

    function Service($http, $localStorage) {
        var service = {};

        service.GetAccounts = GetAccounts;

        return service;

        function GetAccounts(callback) {
            service.accounts = {};
            GetAccountsType(callback, 'acme');
            GetAccountsType(callback, 'ca');
        }

        function GetAccountsType(callback, type) {
            service.accounts[type] = {};
            $http.get('/api/' + type + '/accounts/').then(function (response) {
                response.data.accounts.forEach(function(item, index) {
                    service.accounts[type][item.id] = item;
                    //console.log('requesting certificates for ' + type + ' account id ' + item.id);
                    GetCertificates(callback, type, item.id);
                });
                callback(true);
            });
        }

        function GetCertificates(callback, type, account_id)
        {
            service.accounts[type][account_id]['certificates'] = {};
            $http.get('/api/' + type + '/accounts/' + account_id + '/certificates').then(function (response) {
                //console.log('got success for certs acct type ' + type + ' account id ' + account_id)
                response.data.certificates.forEach(function(item, index) {
                    service.accounts[type][account_id]['certificates'][item.id] = item;
                });
                callback(true);
            });
        }
    }
})();
