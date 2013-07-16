package com.cnnic.whois.web;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.cnnic.whois.util.WhoisProperties;
import com.cnnic.whois.util.WhoisUtil;

public class WhoisFilter implements Filter {

	/**
	 * Called by the web container to indicate to a filter that it is being
	 * taken out of service. This method is only called once all threads within
	 * the filter's doFilter method have exited or after a timeout period has
	 * passed. After the web container calls this method, it will not call the
	 * doFilter method again on this instance of the filter.
	 */
	@Override
	public void destroy() {
		// TODO Auto-generated method stub
	}

	/**
	 * The doFilter method of the Filter is called by the container each time a
	 * request/response pair is passed through the chain due to a client request
	 * for a resource at the end of the chain. The FilterChain passed in to this
	 * method allows the Filter to pass on the request and response to the next
	 * entity in the chain.
	 */
	@Override
	public void doFilter(ServletRequest arg0, ServletResponse arg1,
			FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) arg0;
		HttpServletResponse response = (HttpServletResponse) arg1;

		String role = "anonymous";
		if (request.isUserInRole("authenticated"))
			role = "authenticated";
		if (request.isUserInRole("root"))
			role = "root";
		long currentTime = new Long(System.currentTimeMillis());

		long accessTime = currentTime;
		
		boolean isQueryOverTime = queryControl(request.getRemoteAddr(),
				accessTime, role);
		if (isQueryOverTime) {
			chain.doFilter(request, response);
			
		} else {
			response.sendError(429);
		}
	}

	/**
	 * Called by the web container to indicate to a filter that it is being
	 * placed into service. The servlet container calls the init method exactly
	 * once after instantiating the filter. The init method must complete
	 * successfully before the filter is asked to do any filtering work.
	 */
	@Override
	public void init(FilterConfig arg0) throws ServletException {

	}

	/**
	 * Control call this method when the number of queries in a certain period
	 * of time
	 * 
	 * @param accessTime
	 * @param role
	 * @param userIp
	 * @return If you meet certain requirements, return true, otherwise returns
	 *         false
	 */
	private boolean queryControl(String userIp, long accessTime, String role) {
		if (WhoisUtil.queryRemoteIPMap.get(userIp) == null) {
			WhoisUtil.queryRemoteIPMap.put(userIp, accessTime);
			return true;
		} else {
		
			long time = accessTime - WhoisUtil.queryRemoteIPMap.get(userIp);
			boolean isOverTime = true;
			
			if (role.equals(WhoisUtil.ANONYMOUS)) {
				if (time <= WhoisProperties.getAnonymousExpireTime())
					isOverTime = false;
			} else if (role.equals(WhoisUtil.AUTHENTICATED)) {
				if (time <= WhoisProperties.getAuthenticatedExpireTime())
					isOverTime = false;
			} else if(role.equals(WhoisUtil.ROOT)){
				if (time <= WhoisProperties.getRootExpireTime())
					isOverTime = false;
			}
			
			WhoisUtil.queryRemoteIPMap.put(userIp, accessTime);
			if (time >= WhoisProperties.getExpireTime())
				WhoisUtil.queryRemoteIPMap.remove(userIp);
			return isOverTime;
		}
	}
}
