/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package es.salenda.grails.plugins.springsecurity.saml

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.userdetails.NoStackUsernameNotFoundException
import grails.transaction.Transactional
import org.springframework.beans.BeanUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
class SpringSamlUserDetailsService extends GormUserDetailsService implements SAMLUserDetailsService {

	// Spring bean injected configuration parameters
	String authorityClassName
	String authorityJoinClassName
	String authorityNameField
	Boolean samlUserMustExist
	Boolean samlAutoCreateActive
	Boolean samlAutoAssignAuthorities = true
	String samlAutoCreateKey
	Map samlUserAttributeMappings
	Map samlUserGroupToRoleMapping
	String samlUserGroupAttribute
	String userDomainClassName

	private Class<?> userDomainClass = null // User domain class, cached for performance


	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {

		if (credential) {
			String username = getSamlUsername(credential)
			if (!username) {
				throw new UsernameNotFoundException("No username supplied in saml response.")
			}

			// If this user exists, then we want to use the persisted version with proper roles
			def user = loadUserDomainByUsername(username)
			if (samlUserMustExist && user == null) {
				// username must already be a valid user in local database.
				//   SAML is used strictly for authentication: no attributes or roles are used
				log.warn "User not found: $username"
				throw new NoStackUsernameNotFoundException()
			}

			// TODO: if user locked/expired/not enabled then throw exception?
			// Alternative: the caller has to arrange the check, e.g. using AccountStatusUserDetailsChecker
			// Another alternative: loadUserDomainByUsername() does not return disabled users:
			//     They are still created, but only as transient users.
			// Proper logic depends on application scenarios, many variants are possible.

			def grantedAuthorities = user ? loadAuthorities(user, username, true) : []
			if (user == null) {
				user = generateSecurityUser(username)
			}

			// Update attributes and roles from SAML. FUTURE: configurable option to use SAML only for authentication
			user = mapAdditionalAttributes(credential, user)
			if (user) {
				log.debug "Loading database roles for $username..."
				def authorities = getSamlMappedAuthoritiesForUser(credential)


				if (samlAutoCreateActive) {
					user = saveUser(user.class, user, authorities)

					//TODO move to function
					Map whereClause = [:]
					whereClause.put "user", user
					Class<?> UserRoleClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
					UserRoleClass.withTransaction {
						def auths = UserRoleClass.findAllWhere(whereClause).collect { it.role }

						auths.each { authority ->
							def authorityValue = (authority instanceof String) ? authority : authority."$authorityNameField"
							grantedAuthorities.add(new GrantedAuthorityImpl(authorityValue))

						}
					}
					if (samlUserGroupAttribute && !samlAutoAssignAuthorities
							&& !(authorities.size() == 1 && authorities.contains(GormUserDetailsService.NO_ROLE))) {
						// If the user can be persisted, but SAML mapped roles should be transient
						grantedAuthorities.addAll(authorities)
					}

				}
				else {
					grantedAuthorities.addAll(authorities)
				}

				return createUserDetails(user, grantedAuthorities)
			} else {
				throw new InstantiationException('could not instantiate new user')
			}
		}
	}

	protected String getSamlUsername(credential) {

		if (samlUserAttributeMappings?.containsKey('username')) {

			return credential.getAttributeAsString(samlUserAttributeMappings.username)
		} else {
			// if no mapping provided for username attribute then assume it is the returned subject in the assertion
			return credential.nameID?.value
		}
	}

	protected Object mapAdditionalAttributes(credential, user) {
		samlUserAttributeMappings?.each { key, value ->
			// Note that check "user."$key" instanceof String" will fail when field value is null.
			//  Instead, we have to check field type
			Class keyType = grailsApplication.getDomainClass(userDomainClassName).properties.find { prop -> prop.name == "$key" }.type
			if (keyType != null && (keyType.isArray() || Collection.class.isAssignableFrom(keyType))) {
				def attributes = credential.getAttributeAsStringArray(value)
				attributes?.each() { attrValue ->
					if (! user."$key") {
						user."$key" = []
					}
					user."$key" << attrValue
				}
			} else {
				def attrValue = credential.getAttributeAsString(value)
				user."$key" = attrValue
			}
		}
		user
	}

	protected Collection<GrantedAuthority> getSamlMappedAuthoritiesForUser(SAMLCredential credential) {
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthorityImpl>()

		def samlGroups = getSamlGroups(credential)

		samlGroups.each { groupName ->
			def role = samlUserGroupToRoleMapping.get(groupName)
			def authority = getRole(role)

			if (authority) {
				authorities.add(new GrantedAuthorityImpl(authority."$authorityNameField"))
			}
		}
		if ( authorities.size() == 0 ) {
			authorities.add(GormUserDetailsService.NO_ROLE)
		}

		return authorities
	}

	/**
	 * Extract the groups that the user is a member of from the saml assertion.
	 * Expects the saml.userGroupAttribute to specify the saml assertion attribute that holds
	 * returned group membership data.
	 *
	 * Expects the group strings to be of the format "CN=groupName,someOtherParam=someOtherValue"
	 *
	 * @param credential
	 * @return list of groups
	 */
	protected List getSamlGroups(SAMLCredential credential) {
		def userGroups = []

		if (samlUserGroupAttribute) {
			def attributeValues = credential.getAttributeAsStringArray(samlUserGroupAttribute)
			attributeValues.each { groupString ->
				def groupStringValue = groupString
				if ( groupString.startsWith("CN") ) {
					groupString?.tokenize(',').each { token ->
						def keyValuePair = token.tokenize('=')
						if (keyValuePair.first() == 'CN') {
							groupStringValue = keyValuePair.last()
						}
					}
				}
				userGroups << groupStringValue
			}

		}

		userGroups
	}

	protected Object generateSecurityUser(username) {
		if (userDomainClassName) {
			Class<?> UserClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
			if (UserClass) {
				def user = BeanUtils.instantiateClass(UserClass)
				// FUTURE: replace hardwired field names with conf.userLookup.usernamePropertyName and passwordPropertyName
				user.username = username
				user.password = "password"
				return user
			} else {
				throw new ClassNotFoundException("domain class ${userDomainClassName} not found")
			}
		} else {
			throw new ClassNotFoundException("security user domain class undefined")
		}
	}

	/** User domain class is application specific (cannot be statically linked in the plugin),
	 *   but is defined in the configuration, retrieved dynamically via Grails wizardry,
	 *   and cached for efficiency.
	 */
	Class getUserDomainClass() {
		if (!userDomainClass) {
			def conf = SpringSecurityUtils.securityConfig
			String userClassName = conf.userLookup.userDomainClassName
			def dc = grailsApplication.getDomainClass(userClassName)
			if (!dc) {
				throw new IllegalArgumentException("The specified user domain class '$userClassName' is not a domain class")
			}
			userDomainClass = dc.clazz
		}
		return userDomainClass
	}

	/** Get user domain object.
	 *
	 * @param username
	 * @return null if user not found
	 */
	@Transactional(readOnly=true, noRollbackFor=[IllegalArgumentException])
	def loadUserDomainByUsername(String username) {

		Class<?> User = getUserDomainClass()
		def conf = SpringSecurityUtils.securityConfig
		def user = User.findWhere((conf.userLookup.usernamePropertyName): username)
	}

	protected def saveUser(userClazz, user, authorities) {
		if (userClazz && samlAutoCreateActive && samlAutoCreateKey && authorityNameField && authorityJoinClassName) {

			Map whereClause = [:]
			whereClause.put "$samlAutoCreateKey".toString(), user."$samlAutoCreateKey"
			Class<?> joinClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz

			userClazz.withTransaction {
				def existingUser = userClazz.findWhere(whereClause)
				if (!existingUser) {
					if (!saveUserInternal(user)) {
						def save_errors=""
						user.errors.each {
							save_errors+=it
						}
						throw new UsernameNotFoundException("Could not save user ${user} - ${save_errors}");
					}
				} else {
					user = updateUserProperties(existingUser, user)

					if (samlAutoAssignAuthorities) {
						joinClass.removeAll user
					}
					saveUserInternal(user)
				}
				if (samlAutoAssignAuthorities) {
					authorities.each { grantedAuthority ->
						def role = getRole(grantedAuthority."${authorityNameField}")
						joinClass.create(user, role)
					}
				}

			}
		}
		return user
	}

	/** Insert or update the user object. Return true if successful
	 *  This method gives derived classes chance for additional processing before or after save()
	 */
	protected def saveUserInternal(user) {
		user.save()
	}

	protected Object updateUserProperties(existingUser, user) {
		samlUserAttributeMappings.each { key, value ->
			existingUser."$key" = user."$key"
		}
		return existingUser
	}

	protected Object getRole(String authority) {
		if (authority && authorityNameField && authorityClassName) {
			Class<?> Role = grailsApplication.getDomainClass(authorityClassName).clazz
			if (Role) {
				Map whereClause = [:]
				whereClause.put "$authorityNameField".toString(), authority
				Role.findWhere(whereClause)
			} else {
				throw new ClassNotFoundException("domain class ${authorityClassName} not found")
			}
		}
	}
}
