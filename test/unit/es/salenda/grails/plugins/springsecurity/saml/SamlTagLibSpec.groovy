package es.salenda.grails.plugins.springsecurity.saml

import grails.test.mixin.*
import spock.lang.Ignore
import spock.lang.Specification

@TestFor(SamlTagLib)
class SamlTagLibSpec extends Specification {

    @Ignore("currently has a bug and requires rework (no yak shave)")
    void loginLinkRendersCorrectUrl() {
        given:
        def expectedLink = '<a href=\'/saml/login\'>login</a>'

        expect:
        applyTemplate('<sec:loginLink>Logout</sec:loginLink>') == expectedLink
    }

    void loginLinkShouldSetBody() {
        given:
        def body = "Login here"
        def expectedLink = "<a href=\'[:]?idp=null\'>${body}</a>"

        expect:
        applyTemplate("<sec:loginLink>${body}</sec:loginLink>") == expectedLink
    }

    void loginLinkShouldSetClassAttribute() {
        given:
        def expectedClass = 'loginBtn link'
        def expectedLink = "<a href=\'[:]?idp=null\' class=\'$expectedClass\'>Login</a>"

        expect:
        applyTemplate("<sec:loginLink class=\'${expectedClass}\'>Login</sec:loginLink>") == expectedLink
    }

    void loginLinkShouldSetIdAttribute() {
        given:
        def expectedId = 'loginBtn'
        def expectedLink = "<a href=\'[:]?idp=null\' id=\'$expectedId\'>Login</a>"

        expect:
        applyTemplate("<sec:loginLink id=\'${expectedId}\'>Login</sec:loginLink>") == expectedLink
    }

    void logoutLinkShouldRenderCorrectUrl() {
        given:
        mockConfig()
        def expectedLink = '<a href=\'/saml/logout\'>Logout</a>'

        expect:
        applyTemplate('<sec:logoutLink>Logout</sec:logoutLink>') == expectedLink
    }

    void logouLinkShouldDefaultToCoreLogoutUrl() {
        given:
        mockConfig(false)
        def expectedLink = "<a href=\'${SamlTagLib.LOGOUT_SLUG}\'>Logout</a>"

        expect:
        applyTemplate('<sec:logoutLink>Logout</sec:logoutLink>') == expectedLink
    }

    void logouLinkShouldDefaultToCoreLogoutUrlWithLocal() {
        given:
        mockConfig(false)
        def expectedLink = "<a href=\'${SamlTagLib.LOGOUT_SLUG}?local=true\'>Logout</a>"

        expect:
        applyTemplate('<sec:logoutLink local="true">Logout</sec:logoutLink>') == expectedLink
    }


    void logoutLinkShouldSetBody() {
        given:
        mockConfig()
        def body = "Logout here"
        def expectedLink = "<a href=\'/saml/logout\'>${body}</a>"

        expect:
        applyTemplate("<sec:logoutLink>${body}</sec:logoutLink>") == expectedLink
    }

    void logoutLinkShouldSetClassAttribute() {
        given:
        mockConfig()
        def expectedClass = 'logoutBtn link'
        def expectedLink = "<a href=\'/saml/logout\' class=\'$expectedClass\'>Logout</a>"

        expect:
        applyTemplate("<sec:logoutLink class=\'${expectedClass}\'>Logout</sec:logoutLink>") == expectedLink
    }

    void logoutLinkShouldSetIdAttribute() {
        given:
        mockConfig()
        def expectedId = 'logoutBtn'
        def expectedLink = "<a href=\'/saml/logout\' id=\'$expectedId\'>Logout</a>"

        expect:
        applyTemplate("<sec:logoutLink id=\'${expectedId}\'>Logout</sec:logoutLink>") == expectedLink
    }

    private void mockConfig(boolean samlActive = true) {
        SamlTagLib.metaClass.getGrailsApplication = { ->
            return [config: [grails: [plugin: [springsecurity: [saml: [active: samlActive]]]]]]
        }
    }
}