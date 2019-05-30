<%@ page session="false" trimDirectiveWhitespaces="true" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="petclinic" tagdir="/WEB-INF/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!doctype html>
<petclinic:htmlHeaderAlt/>

<body>
<div class="container">
    <div class="row">
        <div class="col-sm-6 col-md-4 col-md-offset-4">
            <h1 class="text-center login-title">Please identify yourself to the petclinic app</h1>
            <div class="account-wall">
                <img class="profile-img" src="https://lh5.googleusercontent.com/-b0-k99FZlyE/AAAAAAAAAAI/AAAAAAAAAAA/eu7opA4byxI/photo.jpg?sz=120"
                     alt="">
                <c:url value="/login" var="loginUrl"/>
                <form action="${loginUrl}" method="post" class="form-signin">
                    <c:if test="${param.error != null}">
                        <p>
                            Invalid username and password.
                        </p>
                    </c:if>
                    <c:if test="${param.logout != null}">
                        <p>
                            You have been logged out.
                        </p>
                    </c:if>
                    <input type="text" class="form-control" id="username" name="username" required autofocus>
                    <input type="password" class="form-control" placeholder="Password" id="password" name="password" required>
                    <input type="hidden"
                           name="${_csrf.parameterName}"
                           value="${_csrf.token}"/>
                    <button class="btn btn-lg btn-primary btn-block" type="submit">Log in</button>
                    <!--label class="checkbox pull-left">
                        <input type="checkbox" value="remember-me">
                        Remember me
                    </label>
                    <a href="#" class="pull-right need-help">Need help? </a><span class="clearfix"></span -->
                </form>
            </div>
            <!-- a href="#" class="text-center new-account">Create an account </a -->
        </div>
    </div>
</div>

</body>
