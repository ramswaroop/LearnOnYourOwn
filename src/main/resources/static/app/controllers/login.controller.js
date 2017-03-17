//angular.module('todoApp')
todoApp.controller('LoginCtrl',function($scope,$rootScope, $http, $state) {
    console.log("in the LoginCtrl");
  //var self = this;
//$scope.credentials = "";

  var authenticate = function(credentials, callback) {

    var headers = $scope.credentials ? {authorization : "Basic "
        + btoa($scope.credentials.email + ":" + $scope.credentials.password)
    } : {};
    
    $http.get('/api/todos', {headers : headers}).then(function(response) {
      if (response.data.name) {
        $rootScope.authenticated = true;
      } else {
        $rootScope.authenticated = false;
      }
      callback && callback();
    }, function() {
      $rootScope.authenticated = false;
      callback && callback();
    });

  };

  authenticate();
  $scope.credentials = {};
  $scope.login = function() {
      authenticate($scope.credentials, function() {
        if ($rootScope.authenticated) {
         $state.go('home');
          $scope.error = false;
        } else {
         $state.go('login');
          $scope.error = true;
        }
      });
  };
});