//angular.module('todoApp')
todoApp.factory('Users', ['$http', function($http) {
	return {
		get: function() {
			return $http.get('/api/users');
		},

		create: function(userData, callback) {
      	$http.post('/api/users/create', userData).then(function (res) {
            	return callback(res.data); 
      		}, 'error')
		},

		delete: function(id) {
			return $http.delete('/api/users/' + id);
		},

		update: function(userData) {
			return $http.put('/api/users/' + userData.id, userData);
			console.log(userData);
		}
	}
}]);