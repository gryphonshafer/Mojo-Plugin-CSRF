# NAME

Mojolicious::Plugin::CSRF - Cross Site Request Forgery (CSRF) "prevention" Mojolicious plugin

# VERSION

version 1.03

[![test](https://github.com/gryphonshafer/Mojo-Plugin-CSRF/workflows/test/badge.svg)](https://github.com/gryphonshafer/Mojo-Plugin-CSRF/actions?query=workflow%3Atest)
[![codecov](https://codecov.io/gh/gryphonshafer/Mojo-Plugin-CSRF/graph/badge.svg)](https://codecov.io/gh/gryphonshafer/Mojo-Plugin-CSRF)

# SYNOPSIS

    # Simple Mojolicious
    $app->plugin('CSRF');

    my $token = $app->csrf->token;                 # returns the current token
    my $url   = $app->csrf->url_for('/some/path'); # returns a Mojo::URL object

    $app->csrf->delete_token;

    $app->csrf->setup;
    my $result = $app->csrf->check;

    # Customized Mojolicious
    use Crypt::Random;
    use Mojo::DOM;
    use Mojo::Util;
    $app->plugin( CSRF => {
        generate_token => sub {
            Mojo::Util::md5_sum(
                '' . Crypt::Random::makerandom( Size => 50 )
            )
        },

        token_name => 'csrf_token',
        header     => 'X-CSRF-Token',
        methods    => [ qw( POST PUT DELETE PATCH ) ],
        include    => [ '^/' ],
        exclude    => [ '^/api/[^/]+/user/log(?:in|out)/test$' ],

        on_success => sub {
            my ($c) = @_;
            $c->log->info('CSRF check success');
            return 1;
        },

        on_failure => sub {
            my ($c) = @_;
            $c->reply->exception(
                'Access Forbidden: CSRF check failure',
                { status => 403 },
            );
            return 0;
        },

        hooks => [
            before_routes => sub {
                my ($c) = @_;
                $c->csrf->setup;
                $c->csrf->check;
            },

            after_render => sub {
                my ( $c, $output, $format ) = @_;

                if ( $format eq 'html' and $$output ) {
                    my $dom = Mojo::DOM->new(
                        Mojo::Util::decode( 'UTF-8', $$output )
                    );
                    my $forms = $dom->find('form[method="post"]');

                    if ( $forms->size ) {
                        $forms->each( sub {
                            $_->append_content(
                                '<input type="hidden" ' .
                                    'name="'  . $c->csrf->token_name . '" ' .
                                    'value="' . $c->csrf->token . '">'
                            );
                        } );
                        $$output = Mojo::Util::encode( 'UTF-8', $dom->to_string );
                    }
                }
            },
        ],
    } );

    # Mojolicious::Lite
    plugin('CSRF');

# DESCRIPTION

This module is a [Mojolicious](https://metacpan.org/pod/Mojolicious) plugin for Cross Site Request Forgery (CSRF)
"prevention" (theoretically; if used correctly; caveat emptor).

By default, when used, the plugin will cause requests methods that traditionally
contain data-changing actions (i.e. POST, PUT, etc.) to check a generated session
token against a token from a form value, URL parameter, or HTTP header. On
failure, a [Mojo::Exception](https://metacpan.org/pod/Mojo%3A%3AException) is thrown.

# METHODS

The plugin provides a `csrf` helper from which some methods can be called.

## token

This method will return the current token. If there is no current token, this
method will first call the `generate_token` method, store the new token in the
[Mojolicious](https://metacpan.org/pod/Mojolicious) session, and then return the new token.

    my $token = $app->csrf->token;

## url\_for

This is a wrapper around `url_for` from [Mojolicious::Plugin::DefaultHelpers](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3ADefaultHelpers),
returning a [Mojo::URL](https://metacpan.org/pod/Mojo%3A%3AURL) object with the current token merged as a parameter.

    # returns a Mojo::URL object
    my $url  = $app->csrf->url_for('/some/path');
    my $url2 = $app->csrf->url_for('/some/other/path')->query({ answer => 42 });

## delete\_token

This method deletes the current token from the [Mojolicious](https://metacpan.org/pod/Mojolicious) session.

    $app->csrf->delete_token;

## setup

This method should be called prior to rendering a page that precedes a request
where `check` is called. (All this does is set the HTTP header.)

    $app->csrf->setup;

## check

This method checks the current token (saved in the [Mojolicious](https://metacpan.org/pod/Mojolicious) session)
against a token value from a form value, URL parameter, or HTTP header.

    my $result = $app->csrf->check;

The method will call `on_success` or `on_failure` after a check.

# SETTINGS

Almost everything can be customized from the `plugin` call by providing a
hashref of stuff.

## generate\_token

This is a code reference that when called is expected to generate a new token
and return it (though not save it). This subroutine is called by `token` when
it needs to generate a token.

## token\_name

This is the form/URL parameter name containing the comparison token. By default,
it's "csrf\_token".

## header

This is the HTTP header name containing the comparison token. By default,
it's "X-CSRF-Token".

## methods

These are the methods where a comparison check will be performed. You can specify
the set of methods in an arrayref of strings. By default, it's:

    [ qw( POST PUT DELETE PATCH ) ]

If you set "any", then all methods are checked:

    ['any']

## include

This is an arrayref of strings of regular expressions representing URL paths to
include checks on. If not defined, then all paths are checked.

## exclude

This is an arrayref of strings of regular expressions representing URL paths to
exclude checks on.

## on\_success

This is the code reference called when a check is successful. It'll be passed
the application object.

    on_success => sub {
        my ($c) = @_;
        $c->log->info('CSRF check success');
        return 1;
    },

## on\_failure

This is the code reference called when a check fails. It'll be passed the
application object.

    on_failure => sub {
        my ($c) = @_;
        $c->reply->exception(
            'Access Forbidden: CSRF check failure',
            { status => 403 },
        );
        return 0;
    },

## hooks

This is an arrayref of hook names and code references the plugin will install
during it's registration. You could easily (and probably more cleanly) just do
this yourself as you prefer; but by default, this plugin will set
a `before_routes` hook and a `after_render` hook as follows:

    hooks => [
        before_routes => sub {
            my ($c) = @_;
            $c->csrf->setup;
            $c->csrf->check;
        },

        after_render => sub {
            my ( $c, $output, $format ) = @_;

            if ( $format eq 'html' and $$output ) {
                my $dom = Mojo::DOM->new(
                    Mojo::Util::decode( 'UTF-8', $$output )
                );
                my $forms = $dom->find('form[method="post"]');

                if ( $forms->size ) {
                    $forms->each( sub {
                        $_->append_content(
                            '<input type="hidden" ' .
                                'name="'  . $c->csrf->token_name . '" ' .
                                'value="' . $c->csrf->token . '">'
                        );
                    } );
                    $$output = Mojo::Util::encode( 'UTF-8', $dom->to_string );
                }
            }
        },
    ],

# SEE ALSO

[Mojolicious](https://metacpan.org/pod/Mojolicious), [Mojolicious::Plugin](https://metacpan.org/pod/Mojolicious%3A%3APlugin), [Mojolicious::Plugin::CSRFProtect](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3ACSRFProtect),
[Mojolicious::Plugin::DeCSRF](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3ADeCSRF), [Mojolicious::Plugin::CSRFDefender](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3ACSRFDefender).

You can also look for additional information at:

- [GitHub](https://github.com/gryphonshafer/Mojo-Plugin-CSRF)
- [MetaCPAN](https://metacpan.org/pod/Mojolicious::Plugin::CSRF)
- [GitHub Actions](https://github.com/gryphonshafer/Mojo-Plugin-CSRF/actions)
- [Codecov](https://codecov.io/gh/gryphonshafer/Mojo-Plugin-CSRF)
- [CPANTS](http://cpants.cpanauthors.org/dist/Mojo-Plugin-CSRF)
- [CPAN Testers](http://www.cpantesters.org/distro/M/Mojo-Plugin-CSRF.html)

# AUTHOR

Gryphon Shafer <gryphon@cpan.org>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2025-2050 by Gryphon Shafer.

This is free software, licensed under:

    The Artistic License 2.0 (GPL Compatible)
