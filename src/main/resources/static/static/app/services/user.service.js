todoApp.factory('Users', ['$http', function($http) {
	return {
		get: function() {
			return $http.get('/api/users');
		},

		create: function(userData) {
			console.log(userData);
			return $http.post('/api/users', userData);
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