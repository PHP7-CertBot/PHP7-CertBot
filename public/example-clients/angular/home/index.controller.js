(function () {
    'use strict';

    angular
        .module('app')
        .controller('Home.IndexController', Controller);

    function Controller($location, CertbotService) {
        var vm = this;

        initController();

        vm.messages = 'Loading Accounts...';
        vm.accounts = {};

        function initController() {
            CertbotService.GetAccounts(function (result) {
                console.log('callback from CertbotService.AcmeAccounts responded ' + result);
                vm.accounts = CertbotService.accounts;
                vm.messages = JSON.stringify(vm.accounts, null, "    ");
                //$scope.accounts = vm.accounts;
            });
        }
    }

})();
