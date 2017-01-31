
todoApp.controller('UserController', ['Users','$scope','$http', function UserController(Users, $scope, $http) {
    console.log("in user controller");

    $scope.formModel = {};
	$scope.submitting = false;
	$scope.submitted = false;
	$scope.has_error = false;

	Users.get()
    .success(function(data) {
        $scope.users = data;
    });

	$scope.createUser = function() {
        if(!$scope.userForm.$valid) {
            return;
        }
		Users.create($scope.formModel)
		.success(function(data){
			console.log(":)");
			$scope.submitting = false;
			$scope.submitted = true;
			$scope.has_error = false;
		}).error(function(data) {
			console.log(":(");
			$scope.submitting = false;
 			$scope.submitted = false;
 			$scope.has_error = true;
		});
        // Users.create($scope.formModel)
		// console.log($scope.formModel)
        // .success(function(data) {
        //     $scope.formModel = {}; // clear the form so our user is ready to enter another
        //     $scope.users.push(data);
        // });
    };

	// $scope.submitting = false;
	// $scope.submitted = false;

    // $scope.onSubmit = function () {
	// 	$scope.submitting = true;
	// 	console.log("Hey i'm submitted!");
	// 	console.log($scope.formModel);

    //     $http.post('https://minmax-server.herokuapp.com/register/', $scope.formModel).
	// 		success(function (data) {
	// 			console.log(":)");
	// 			$scope.submitting = false;
	// 			$scope.submitted = true;
	// 			$scope.has_error = false;
	// 		}).error(function(data) {
	// 			console.log(":(");
	// 			$scope.submitting = false;
	// 			$scope.submitted = false;
	// 			$scope.has_error = true;
	// 		});

    // };


}]);