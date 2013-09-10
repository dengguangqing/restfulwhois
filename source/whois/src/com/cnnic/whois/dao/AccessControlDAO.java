package com.cnnic.whois.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.WhoisUtil;

public class AccessControlDAO {
	private static AccessControlDAO accessControlDAO = new AccessControlDAO();
	private DataSource ds;

	/**
	 * Connect to the datasource in the constructor
	 * 
	 * @throws IllegalStateException
	 */
	private AccessControlDAO() throws IllegalStateException {
		try {
			InitialContext ctx = new InitialContext();
			ds = (DataSource) ctx.lookup(WhoisUtil.JNDI_NAME);
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalStateException(e.getMessage());
		}
	}

	/**
	 * Get ExColumnDAO objects
	 * 
	 * @return ExColumnDAO objects
	 */
	public static AccessControlDAO getAccessControlDAO() {
		return accessControlDAO;
	}

	/**
	 * List permission information
	 * 
	 * @param tableName
	 * @return map
	 * @throws ManagementException
	 */
	public Map<String, Object> listPermissionCoulumn(String tableName)
			throws ManagementException {
		Connection connection = null;
		PreparedStatement stmt = null;
		Map<String, Object> permissionList = new HashMap<String, Object>();

		try {
			connection = ds.getConnection();
			stmt = connection
					.prepareStatement(WhoisUtil.SELECT_COLUMNINFOERMISSION);
			stmt.setString(1, tableName);
			ResultSet results = stmt.executeQuery();

			while (results.next()) {
				String columnName = results.getString(WhoisUtil.COLUMNNAME);
				Map<String, String> userList = new HashMap<String, String>();
				userList.put(WhoisUtil.ANONYMOUS,
						results.getString(WhoisUtil.ANONYMOUS));
				userList.put(WhoisUtil.AUTHENTICATED,
						results.getString(WhoisUtil.AUTHENTICATED));
				userList.put(WhoisUtil.ROOT, results.getString(WhoisUtil.ROOT));
				permissionList.put(columnName, userList);
			}
			return permissionList;
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException se) {
				}
			}
		}
	}

	/**
	 * Update permission information
	 * 
	 * @param tableName
	 * @param permissionList
	 * @throws ManagementException
	 */
	public void updatePermission(String tableName,
			Map<String, List<String>> permissionList)
			throws ManagementException {
		Set<String> columnkeySet = permissionList.keySet();
		Connection connection = null;
		PreparedStatement stmt = null;

		try {
			connection = ds.getConnection();
			stmt = connection.prepareStatement(WhoisUtil.UPDATE_PERMISSION);
			for (String key : columnkeySet) {
				List<String> permissionValueList = (List<String>) permissionList
						.get(key);
				stmt.setString(1, permissionValueList.get(0));
				stmt.setString(2, permissionValueList.get(1));
				stmt.setString(3, permissionValueList.get(2));
				stmt.setString(4, tableName);
				stmt.setString(5, key);
				stmt.execute();
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException se) {
				}
			}
		}
	}
}
