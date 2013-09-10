<%@ page import="java.security.Principal"%>
<%@ page language="java" import="java.util.*" pageEncoding="utf-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ page session="true"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
	<head>
		<title>Management</title>
		<link href="<c:url value='/css/whois-style.css'/>" type="text/css"
			rel="stylesheet" />

		<script type="text/javascript"
			src="<c:url value='/js/whois-admin.js'/>"></script>
		<script type="text/javascript"
			src="<c:url value='/js/jquery-1.6.2.min.js'/>"></script>
		<script type="text/javascript" src="<c:url value='/js/accordion.js'/>"></script>
		<script type="text/javascript">
	$(function() {
		$(".nav").accordion({
			//accordion: true,
			speed : 500,
			closedSign : '',
			openedSign : ''
		});
	});
	var tableName = null;
</script>
	</head>
	<body>
		<%
			Principal user = request.getUserPrincipal();
			String username = "";
			if (user != null) {
				username = user.getName();
			}
			request.setAttribute("user", user);
			String[] tableNames = {"autnum", "dnrdomain", 
		"dnrentity", "dsData", "errormessage", "events", "ip", "keyData", "link",
			"nameserver", "notices", "phones", "postaladdress", "publicIds", "registrar",
			"remarks", "rirdomain", "rirentity", "secureDNS", "variants"};
		%>

		<div id="wrapper">
			<div id="header">
				<h1>
					<a href="<%= request.getContextPath() %>"><acronym>Restful Whois</acronym> </a>
				</h1>
				<ul id="menu">
					<li class="one">
						<dl>
							<dt>
								<a href="" onclick="aboutContent();return false">About Us</a>
							</dt>
						</dl>
					</li>

					<li class="three">
						<dl>
							<dt>
								<c:choose>
									<c:when test="${empty requestScope.user }">
										<a href="<c:url value='/adv/advindex.jsp'/>">Login</a>
									</c:when>
									<c:otherwise>
										<font>Current User： <big style="color: red"><%=username%></big>
										</font>
									</c:otherwise>
								</c:choose>

							</dt>
						</dl>
					</li>
				</ul>
			</div>
			<div id="sidebar">
				<div id="web_services">
					<fieldset>
						<legend>
							<span>Whois Management</span>
						</legend>
						<br />
						<hr />
						<ul class="nav">
							<li>
								<a href="#">EXTENDS COLUMN</a>
								<ul>
									<c:forEach items="<%=tableNames %>" var="taName">
										<li>
											<a href="" onclick="operation('${taName}');return false">${taName}</a>
										</li>
									</c:forEach>
								</ul>
							</li>
							<hr />
							<li>
								<a href="#">PERMISSIONS</a>
								<ul>
									<c:forEach items="<%=tableNames %>" var="taName">
										<li>
											<a href=""
												onclick="operationPermissionTable('${taName}');return false">${taName}</a>
										</li>
									</c:forEach>
								</ul>
							</li>
							<hr />
							<li>
								<a href="#"">REDIRECTION TBALE</a>
								<ul>
									<li>
										<a href=""
											onclick="operationRedirectTable('autnum');return false">Autnum Redirection</a>
									</li>
									<li>
										<a href="" onclick="operationRedirectTable('ip');return false">IP Redirection</a>
									</li>
									<li>
										<a href=""
											onclick="operationRedirectTable('domain');return false">Domain Redirection</a>
									</li>
								</ul>
							</li>

						</ul>
					</fieldset>
				</div>
			</div>
			<div id="content">
				<div id="maincontent">
				</div>
			</div>
			<div style="clear: both;"></div>
		</div>
		<div id="footer">
			<p>
				By using the Restful Whois service, you are agreeing to the
				<a href="/whois_tou.html" class="footer_link">Whois Terms of Use</a>
				<br />
				&copy; Copyright 2013, CNNIC & ICANN
			</p>
			<img name='image1' alt="" src="<c:url value='/image/cnnicLogo.jpg'/>">
			<img alt="" name='image2' src="<c:url value='/image/icannLogo.jpg'/>">
		</div>
	</body>
</html>
