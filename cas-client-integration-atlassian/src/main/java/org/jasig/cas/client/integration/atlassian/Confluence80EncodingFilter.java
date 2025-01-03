package org.jasig.cas.client.integration.atlassian;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.AbstractConfigurationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Confluence80EncodingFilter sets the character-encoding of the request to the configured encoding (default: "UTF-8").
 * This filter needs to be added before the other CAS-Filters because they will access request-parameters.
 * Accessing request-parameters for post-requests without the proper encoding will also affect all subsequent filters (e.g. Confluence)
 * because the request-parameters are cached once they have been read.
 */
public class Confluence80EncodingFilter extends AbstractConfigurationFilter {

    private final String UTF8 = java.nio.charset.StandardCharsets.UTF_8.name();

    private String encoding = UTF8;

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        this.encoding = getString(ConfigurationKeys.ENCODING);
        if (StringUtils.isEmpty(this.encoding)) {
            this.encoding = UTF8;
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        request.setCharacterEncoding(this.encoding);
        filterChain.doFilter(request, servletResponse);
    }

    @Override
    public void destroy() {
        super.destroy();
    }
}
