package test;


import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import javax.sql.DataSource;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.NestedLdapAuthoritiesPopulator;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.ArrayList;
import java.util.List;



/**
 * UserDetailService for aggregating user's permissions
 * from database roles and Active Directory (AD) groups
 *
 * @author TSaha
 *
 */
public class JdbcLdapUserDetailsService implements UserDetailsService  {

    private final LdapContextSource ldapContextSource;
    private final JdbcDaoImpl jdbcDao;
    private final String ldapUserSearchBase;    // User search base in AD
    private final String ldapUserSearchFilter;  // User filter in AD
    private final String ldapGroupSearchBase;   // Group search base in AD

    public JdbcLdapUserDetailsService( final DataSource dataSource,
            final LdapContextSource ldapContextSource, final String jdbcUsersByUsernameQuery,
            final String jdbcAuthoritiesByUsernameQuery,
            final String userSearchBase, final String userSearchFilter,
            final String groupSearchBase){
        jdbcDao= new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        this.ldapContextSource=ldapContextSource;
        jdbcDao.setUsersByUsernameQuery(jdbcUsersByUsernameQuery);
        jdbcDao.setAuthoritiesByUsernameQuery(jdbcAuthoritiesByUsernameQuery);
        this.ldapUserSearchBase=userSearchBase;
        this.ldapUserSearchFilter=userSearchFilter;
        this.ldapGroupSearchBase=groupSearchBase;
    }

    public UserDetails loadUserByUsername(final String username)
            throws UsernameNotFoundException
    {
        System.out.println("Getting access details from database !!");
        final UserDetails jdbcUser=jdbcDao.loadUserByUsername(username);
        final FilterBasedLdapUserSearch ldapUserSearch = new FilterBasedLdapUserSearch(this.ldapUserSearchBase,
                this.ldapUserSearchFilter, ldapContextSource);
        final NestedLdapAuthoritiesPopulator ldapAuth= new NestedLdapAuthoritiesPopulator(
                ldapContextSource,this.ldapGroupSearchBase);
        ldapAuth.setSearchSubtree(true);
        ldapAuth.setConvertToUpperCase(false);
        ldapAuth.setIgnorePartialResultException(true);
        final LdapUserDetailsService ldapUserDetailsService=new LdapUserDetailsService(ldapUserSearch,
                ldapAuth);
        System.out.println("Getting access details from AD !!");
        final UserDetails ldapUser=ldapUserDetailsService.loadUserByUsername(username);
        final List<GrantedAuthority>  authorities= new ArrayList<GrantedAuthority>();

        System.out.println("Jdbc Authorities are...");
        for(GrantedAuthority authority: jdbcUser.getAuthorities()){
            System.out.println(authority);
        }
        authorities.addAll(jdbcUser.getAuthorities());

        System.out.println("Ldap Authorities are...");

        for(GrantedAuthority authority: ldapUser.getAuthorities()){
            System.out.println(authority.getAuthority());
            authorities.add(new SimpleGrantedAuthority(authority.getAuthority()));
        }

        final UserDetails user = new User(jdbcUser.getUsername(), "password",
                true, true, true, true, authorities);
        return user;
    }
}
