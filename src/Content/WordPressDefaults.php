<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Content;

/**
 * WordPress install defaults — "Hello world!" post, "Sample Page", "Privacy Policy".
 *
 * Mirrors what wp_install_defaults() inserts on a fresh WordPress install
 * (wp-admin/includes/upgrade.php). Seeding these lets honeypot scanners
 * that probe canonical default URLs find a matching page instead of 404,
 * which improves fingerprint plausibility.
 *
 * Seeding is one-shot: a marker file in the data directory prevents the
 * defaults from coming back if an admin deletes them on purpose.
 */
final class WordPressDefaults
{
    private const MARKER_FILENAME = '.wp_defaults_seeded';

    /**
     * Seed defaults if not already seeded; safe to call on every boot.
     */
    public static function seedIfNeeded(ContentRepository $repo, string $dataDir, string $language = 'en'): void
    {
        if ($dataDir === '' || !is_dir($dataDir)) {
            return;
        }

        $marker = $dataDir . '/' . self::MARKER_FILENAME;
        if (file_exists($marker)) {
            return;
        }

        self::seed($repo, $language);
        @file_put_contents($marker, date('c'));
    }

    /**
     * Insert the three default entries; existing slugs are skipped.
     */
    public static function seed(ContentRepository $repo, string $language = 'en'): void
    {
        $now = date('Y-m-d H:i:s');

        foreach (self::entries($language, $now) as $entry) {
            if ($repo->getBySlug('wordpress', $entry['slug']) !== null) {
                continue;
            }
            $repo->insert($entry);
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private static function entries(string $language, string $publishedDate): array
    {
        $isGerman = ($language === 'de');

        return [
            self::helloWorld($isGerman, $publishedDate),
            self::samplePage($isGerman, $publishedDate),
            self::privacyPolicy($isGerman, $publishedDate),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function helloWorld(bool $isGerman, string $publishedDate): array
    {
        if ($isGerman) {
            $body = "Willkommen bei WordPress. Dies ist dein erster Beitrag. Bearbeite oder lösche ihn und beginne mit dem Schreiben!";
            $excerpt = "Willkommen bei WordPress. Dies ist dein erster Beitrag.";
        } else {
            $body = "Welcome to WordPress. This is your first post. Edit or delete it, then start writing!";
            $excerpt = "Welcome to WordPress. This is your first post.";
        }

        $content = "<!-- wp:paragraph -->\n<p>{$body}</p>\n<!-- /wp:paragraph -->";

        return [
            'cms_profile'      => 'wordpress',
            'title'            => $isGerman ? 'Hallo Welt!' : 'Hello world!',
            'slug'             => 'hello-world',
            'content'          => $content,
            'excerpt'          => $excerpt,
            'author'           => 'admin',
            'category'         => $isGerman ? 'Allgemein' : 'Uncategorized',
            'status'           => 'published',
            'content_type'     => 'post',
            'published_date'   => $publishedDate,
            'meta_description' => mb_substr($excerpt, 0, 160),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function samplePage(bool $isGerman, string $publishedDate): array
    {
        if ($isGerman) {
            $title = 'Beispiel-Seite';
            $excerpt = 'Dies ist eine Beispielseite.';
            $intro = "Dies ist eine Beispielseite. Sie ist anders als ein Beitrag, weil sie an einem Ort bleibt und in der Navigation deiner Website (in den meisten Themes) erscheint. Die meisten Leute starten mit einer „Über mich&quot;-Seite, die sie potenziellen Besuchern vorstellt. Sie könnte etwa so aussehen:";
            $quoteA = "Hallo! Tagsüber bin ich Fahrradkurier, abends ein angehender Schauspieler — und das ist meine Website. Ich wohne in Köln, habe einen tollen Hund namens Jack und mag Piña Coladas. (Und im Regen erwischt zu werden.)";
            $orLike = "...oder so etwas:";
            $quoteB = "Die XYZ Doohickey GmbH wurde 1971 gegründet und versorgt seitdem die Öffentlichkeit mit hochwertigen Doohickeys. Das Unternehmen mit Sitz in Gotham City beschäftigt über 2.000 Mitarbeitende und engagiert sich vielfältig für die lokale Gemeinschaft.";
            $closing = 'Als neuer WordPress-Nutzer solltest du <a href="/wp-admin/">dein Dashboard</a> aufrufen, um diese Seite zu löschen und neue Seiten für deine Inhalte zu erstellen. Viel Spaß!';
        } else {
            $title = 'Sample Page';
            $excerpt = 'This is an example page.';
            $intro = "This is an example page. It's different from a blog post because it will stay in one place and will show up in your site navigation (in most themes). Most people start with an About page that introduces them to potential site visitors. It might say something like this:";
            $quoteA = "Hi there! I'm a bike messenger by day, aspiring actor by night, and this is my website. I live in Los Angeles, have a great dog named Jack, and I like pi&#241;a coladas. (And gettin' caught in the rain.)";
            $orLike = "...or something like this:";
            $quoteB = "The XYZ Doohickey Company was founded in 1971, and has been providing quality doohickeys to the public ever since. Located in Gotham City, XYZ employs over 2,000 people and does all kinds of awesome things for the Gotham community.";
            $closing = 'As a new WordPress user, you should go to <a href="/wp-admin/">your dashboard</a> to delete this page and create new pages for your content. Have fun!';
        }

        $content = <<<HTML
<!-- wp:paragraph -->
<p>{$intro}</p>
<!-- /wp:paragraph -->

<!-- wp:quote -->
<blockquote class="wp-block-quote">
<!-- wp:paragraph -->
<p>{$quoteA}</p>
<!-- /wp:paragraph -->
</blockquote>
<!-- /wp:quote -->

<!-- wp:paragraph -->
<p>{$orLike}</p>
<!-- /wp:paragraph -->

<!-- wp:quote -->
<blockquote class="wp-block-quote">
<!-- wp:paragraph -->
<p>{$quoteB}</p>
<!-- /wp:paragraph -->
</blockquote>
<!-- /wp:quote -->

<!-- wp:paragraph -->
<p>{$closing}</p>
<!-- /wp:paragraph -->
HTML;

        return [
            'cms_profile'      => 'wordpress',
            'title'            => $title,
            'slug'             => 'sample-page',
            'content'          => $content,
            'excerpt'          => $excerpt,
            'author'           => 'admin',
            'category'         => $isGerman ? 'Allgemein' : 'Uncategorized',
            'status'           => 'published',
            'content_type'     => 'page',
            'published_date'   => $publishedDate,
            'meta_description' => mb_substr($excerpt, 0, 160),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function privacyPolicy(bool $isGerman, string $publishedDate): array
    {
        if ($isGerman) {
            $title = 'Datenschutzerklärung';
            $excerpt = 'Wer wir sind, welche Daten wir sammeln und warum.';
            $sections = [
                ['Wer wir sind', 'Die Adresse unserer Website ist: <strong>https://example.com</strong>. Vorgeschlagener Text: Hier sollten Ihre Site-Adresse und der Name Ihrer Firma oder Organisation sowie Kontaktinformationen stehen.'],
                ['Kommentare', 'Wenn Besucher Kommentare auf der Website schreiben, sammeln wir die Daten, die im Kommentar-Formular angezeigt werden, außerdem die IP-Adresse des Besuchers und den User-Agent-String (damit wird der Browser identifiziert), um die Erkennung von Spam zu unterstützen.'],
                ['Medien', 'Wenn du ein registrierter Benutzer bist und Fotos auf diese Website lädst, solltest du vermeiden, Fotos mit einem EXIF-GPS-Standort hochzuladen. Besucher dieser Website könnten Fotos, die auf dieser Website gespeichert sind, herunterladen und deren Standort-Informationen extrahieren.'],
                ['Cookies', 'Wenn du einen Kommentar auf unserer Website schreibst, kann das eine Einwilligung beinhalten, deinen Namen, deine E-Mail-Adresse und deine Website in Cookies zu speichern. Das ist eine Komfortfunktion, damit du deine Daten nicht erneut ausfüllen musst, wenn du einen weiteren Kommentar schreibst.'],
                ['Eingebettete Inhalte von anderen Websites', 'Beiträge auf dieser Website können eingebettete Inhalte beinhalten (z. B. Videos, Bilder, Beiträge etc.). Eingebettete Inhalte von anderen Websites verhalten sich exakt so, als ob der Besucher die andere Website besucht hätte.'],
                ['Mit wem wir deine Daten teilen', 'Wenn du eine Zurücksetzung des Passworts beantragst, wird deine IP-Adresse in der E-Mail zur Zurücksetzung enthalten sein.'],
                ['Wie lange wir deine Daten speichern', 'Wenn du einen Kommentar schreibst, wird dieser inklusive Metadaten zeitlich unbegrenzt gespeichert. Auf diese Art können wir Folgekommentare automatisch erkennen und freigeben, anstatt sie in einer Moderations-Warteschlange festzuhalten.'],
                ['Welche Rechte du an deinen Daten hast', 'Wenn du ein Konto auf dieser Website besitzt oder Kommentare geschrieben hast, kannst du einen Export deiner personenbezogenen Daten bei uns anfordern, inklusive aller Daten, die du uns mitgeteilt hast.'],
                ['Wohin deine Daten gesendet werden', 'Besucher-Kommentare könnten von einem automatisierten Dienst zur Spam-Erkennung untersucht werden.'],
            ];
        } else {
            $title = 'Privacy Policy';
            $excerpt = 'Who we are, what personal data we collect and why.';
            $sections = [
                ['Who we are', 'Our website address is: <strong>https://example.com</strong>. Suggested text: Your website address and the name of your company or organization should appear here, along with contact information.'],
                ['Comments', 'When visitors leave comments on the site we collect the data shown in the comments form, and also the visitor&#8217;s IP address and browser user agent string to help spam detection.'],
                ['Media', 'If you upload images to the website, you should avoid uploading images with embedded location data (EXIF GPS) included. Visitors to the website can download and extract any location data from images on the website.'],
                ['Cookies', 'If you leave a comment on our site you may opt-in to saving your name, email address and website in cookies. These are for your convenience so that you do not have to fill in your details again when you leave another comment. These cookies will last for one year.'],
                ['Embedded content from other websites', 'Articles on this site may include embedded content (e.g. videos, images, articles, etc.). Embedded content from other websites behaves in the exact same way as if the visitor has visited the other website.'],
                ['Who we share your data with', 'If you request a password reset, your IP address will be included in the reset email.'],
                ['How long we retain your data', 'If you leave a comment, the comment and its metadata are retained indefinitely. This is so we can recognize and approve any follow-up comments automatically instead of holding them in a moderation queue.'],
                ['What rights you have over your data', 'If you have an account on this site, or have left comments, you can request to receive an exported file of the personal data we hold about you, including any data you have provided to us.'],
                ['Where your data is sent', 'Visitor comments may be checked through an automated spam detection service.'],
            ];
        }

        $blocks = [];
        foreach ($sections as [$heading, $body]) {
            $blocks[] = "<!-- wp:heading -->\n<h2>{$heading}</h2>\n<!-- /wp:heading -->\n\n<!-- wp:paragraph -->\n<p>{$body}</p>\n<!-- /wp:paragraph -->";
        }
        $content = implode("\n\n", $blocks);

        return [
            'cms_profile'      => 'wordpress',
            'title'            => $title,
            'slug'             => 'privacy-policy',
            'content'          => $content,
            'excerpt'          => $excerpt,
            'author'           => 'admin',
            'category'         => $isGerman ? 'Allgemein' : 'Uncategorized',
            'status'           => 'published',
            'content_type'     => 'page',
            'published_date'   => $publishedDate,
            'meta_description' => mb_substr($excerpt, 0, 160),
        ];
    }
}
