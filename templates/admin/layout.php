<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:;">
    <title><?= htmlspecialchars($page_title ?? 'Admin', ENT_QUOTES, 'UTF-8') ?> - ReportedIP Honeypot</title>
    <style>
        /* ============================================================
           ReportedIP Design System — CSS Custom Properties
           ============================================================ */
        :root {
            /* Primary */
            --rip-primary: #4F46E5;
            --rip-primary-hover: #4338CA;
            --rip-primary-light: #E0E7FF;
            --rip-primary-dark: #3730A3;

            /* Success / Danger / Warning / Info */
            --rip-success: #10B981;
            --rip-success-light: #ECFDF5;
            --rip-success-border: #A7F3D0;
            --rip-success-text: #065F46;

            --rip-danger: #EF4444;
            --rip-danger-light: #FEF2F2;
            --rip-danger-border: #FECACA;
            --rip-danger-text: #991B1B;

            --rip-warning: #F59E0B;
            --rip-warning-light: #FFFBEB;
            --rip-warning-border: #FDE68A;
            --rip-warning-text: #92400E;

            --rip-info: #6366F1;
            --rip-info-light: #EEF2FF;
            --rip-info-border: #C7D2FE;
            --rip-info-text: #3730A3;

            /* Neutrals */
            --rip-gray-50: #F9FAFB;
            --rip-gray-100: #F3F4F6;
            --rip-gray-200: #E5E7EB;
            --rip-gray-300: #D1D5DB;
            --rip-gray-400: #9CA3AF;
            --rip-gray-500: #6B7280;
            --rip-gray-600: #4B5563;
            --rip-gray-700: #374151;
            --rip-gray-800: #1F2937;
            --rip-gray-900: #111827;

            /* Background */
            --rip-bg: #F0F2F5;
            --rip-bg-card: #FFFFFF;
            --rip-bg-code: #F8FAFC;

            /* Sidebar Gradient */
            --rip-gradient-dark: linear-gradient(180deg, #1F2937 0%, #111827 100%);
            --rip-sidebar-border: rgba(255,255,255,0.08);
            --rip-sidebar-text: #D1D5DB;
            --rip-sidebar-text-hover: #FFFFFF;
            --rip-sidebar-active-bg: rgba(79,70,229,0.15);
            --rip-sidebar-active-text: #A5B4FC;
            --rip-sidebar-active-border: #4F46E5;

            /* Typography */
            --rip-font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --rip-font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            --rip-font-size-xs: 11px;
            --rip-font-size-sm: 12px;
            --rip-font-size-base: 13px;
            --rip-font-size-md: 14px;
            --rip-font-size-lg: 16px;
            --rip-font-size-xl: 18px;
            --rip-font-size-2xl: 28px;
            --rip-font-size-3xl: 32px;
            --rip-line-height: 1.5;

            /* Spacing */
            --rip-space-xs: 4px;
            --rip-space-sm: 8px;
            --rip-space-md: 12px;
            --rip-space-lg: 16px;
            --rip-space-xl: 20px;
            --rip-space-2xl: 24px;
            --rip-space-3xl: 28px;

            /* Borders & Radii */
            --rip-radius-sm: 4px;
            --rip-radius-md: 6px;
            --rip-radius-lg: 8px;
            --rip-radius-xl: 10px;
            --rip-radius-full: 9999px;
            --rip-border: 1px solid var(--rip-gray-200);

            /* Shadows */
            --rip-shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --rip-shadow-md: 0 1px 3px rgba(0,0,0,0.08);
            --rip-shadow-lg: 0 4px 12px rgba(0,0,0,0.1);

            /* Transitions */
            --rip-transition: 0.15s ease;

            /* Layout */
            --rip-sidebar-width: 240px;
        }

        /* ============================================================
           Reset & Base
           ============================================================ */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--rip-font-family);
            background: var(--rip-bg);
            color: var(--rip-gray-900);
            display: flex;
            min-height: 100vh;
            font-size: var(--rip-font-md);
            line-height: var(--rip-line-height);
        }

        /* ============================================================
           Sidebar
           ============================================================ */
        .rip-sidebar {
            width: var(--rip-sidebar-width);
            background: var(--rip-gradient-dark);
            color: var(--rip-sidebar-text);
            display: flex;
            flex-direction: column;
            position: fixed;
            top: 0; left: 0; bottom: 0;
            z-index: 100;
        }
        .rip-sidebar__brand {
            padding: var(--rip-space-xl);
            font-size: var(--rip-font-size-lg);
            font-weight: 700;
            color: var(--rip-sidebar-text-hover);
            border-bottom: 1px solid var(--rip-sidebar-border);
            display: flex;
            align-items: center;
            gap: var(--rip-space-sm);
        }
        .rip-sidebar__brand svg { flex-shrink: 0; }
        .rip-sidebar__nav { flex: 1; padding: var(--rip-space-md) 0; }
        .rip-sidebar__nav a {
            display: flex;
            align-items: center;
            gap: var(--rip-space-sm);
            padding: 10px var(--rip-space-xl);
            color: var(--rip-sidebar-text);
            text-decoration: none;
            font-size: var(--rip-font-size-md);
            transition: background var(--rip-transition), color var(--rip-transition);
        }
        .rip-sidebar__nav a:hover {
            background: rgba(255,255,255,0.06);
            color: var(--rip-sidebar-text-hover);
        }
        .rip-sidebar__nav a.active {
            background: var(--rip-sidebar-active-bg);
            color: var(--rip-sidebar-active-text);
            border-left: 3px solid var(--rip-sidebar-active-border);
            padding-left: 17px;
        }
        .rip-sidebar__nav a .icon { width: 18px; text-align: center; font-style: normal; }
        .rip-sidebar__footer {
            padding: var(--rip-space-lg) var(--rip-space-xl);
            border-top: 1px solid var(--rip-sidebar-border);
        }
        .rip-sidebar__footer a { color: var(--rip-sidebar-text); text-decoration: none; font-size: var(--rip-font-size-base); }
        .rip-sidebar__footer a:hover { color: var(--rip-danger); }
        .rip-sidebar__logout-btn {
            background: none; border: none; color: var(--rip-sidebar-text); cursor: pointer;
            font-size: var(--rip-font-size-base); padding: 0; font-family: inherit;
        }
        .rip-sidebar__logout-btn:hover { color: var(--rip-danger); }

        /* ============================================================
           Main Area
           ============================================================ */
        .rip-main { flex: 1; margin-left: var(--rip-sidebar-width); min-height: 100vh; }
        .rip-header {
            background: var(--rip-bg-card);
            padding: var(--rip-space-lg) var(--rip-space-3xl);
            border-bottom: var(--rip-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 50;
        }
        .rip-header h1 { font-size: var(--rip-font-size-xl); font-weight: 600; color: var(--rip-gray-900); }
        .rip-header__meta { font-size: var(--rip-font-size-sm); color: var(--rip-gray-400); }
        .rip-content { padding: var(--rip-space-2xl) var(--rip-space-3xl); }

        /* ============================================================
           Alerts
           ============================================================ */
        .rip-alert { padding: var(--rip-space-md) var(--rip-space-lg); border-radius: var(--rip-radius-md); margin-bottom: var(--rip-space-xl); font-size: var(--rip-font-size-base); }
        .rip-alert--success { background: var(--rip-success-light); color: var(--rip-success-text); border: 1px solid var(--rip-success-border); }
        .rip-alert--error { background: var(--rip-danger-light); color: var(--rip-danger-text); border: 1px solid var(--rip-danger-border); }
        .rip-alert--warning { background: var(--rip-warning-light); color: var(--rip-warning-text); border: 1px solid var(--rip-warning-border); }
        .rip-alert--info { background: var(--rip-info-light); color: var(--rip-info-text); border: 1px solid var(--rip-info-border); }

        /* ============================================================
           Cards
           ============================================================ */
        .rip-card {
            background: var(--rip-bg-card);
            border-radius: var(--rip-radius-lg);
            box-shadow: var(--rip-shadow-md);
            padding: var(--rip-space-xl);
            margin-bottom: var(--rip-space-xl);
        }
        .rip-card__header {
            font-size: var(--rip-font-size-md);
            font-weight: 600;
            color: var(--rip-gray-600);
            margin-bottom: 14px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--rip-gray-100);
        }

        /* ============================================================
           Tables
           ============================================================ */
        .rip-table { width: 100%; border-collapse: collapse; font-size: var(--rip-font-size-base); }
        .rip-table th {
            text-align: left;
            padding: 8px 10px;
            background: var(--rip-gray-50);
            color: var(--rip-gray-600);
            font-weight: 600;
            font-size: var(--rip-font-size-xs);
            text-transform: uppercase;
            letter-spacing: 0.3px;
            border-bottom: 2px solid var(--rip-gray-200);
            white-space: nowrap;
        }
        .rip-table td { padding: 7px 10px; border-bottom: 1px solid var(--rip-gray-100); vertical-align: middle; }
        .rip-table tr:hover td { background: var(--rip-gray-50); }
        .rip-table--compact td { padding: 5px 8px; }
        .rip-table--striped tbody tr:nth-child(even) td { background: var(--rip-gray-50); }

        /* ============================================================
           Badges
           ============================================================ */
        .rip-badge {
            display: inline-block;
            padding: 1px 7px;
            border-radius: var(--rip-radius-full);
            font-size: 10px;
            font-weight: 600;
            line-height: 1.6;
            white-space: nowrap;
            vertical-align: middle;
            letter-spacing: 0.1px;
        }
        .rip-badge--sent { background: #DCFCE7; color: #166534; }
        .rip-badge--pending { background: #FEF3C7; color: #92400E; }
        .rip-badge--method { background: var(--rip-primary-light); color: var(--rip-primary-dark); }
        .rip-badge--cat { background: #F3E8FF; color: #6B21A8; }
        .rip-badge--severity-critical { background: #FEE2E2; color: #B91C1C; }
        .rip-badge--severity-high { background: #FFEDD5; color: #C2410C; }
        .rip-badge--severity-medium { background: #FEF9C3; color: #A16207; }
        .rip-badge--severity-low { background: #DCFCE7; color: #15803D; }
        .rip-badge--whitelisted { background: var(--rip-primary-light); color: var(--rip-primary-dark); }

        /* Visitor type badges */
        .rip-badge--good-bot { background: #DCFCE7; color: #166534; }
        .rip-badge--ai-agent { background: #F3E8FF; color: #6B21A8; }
        .rip-badge--bad-bot { background: #FEE2E2; color: #B91C1C; }
        .rip-badge--hacker { background: #FFEDD5; color: #C2410C; }
        .rip-badge--human { background: var(--rip-primary-light); color: var(--rip-primary-dark); }

        /* Badge group — horizontal flow for table cells */
        .rip-badge-group {
            display: flex;
            flex-wrap: wrap;
            gap: 3px;
            align-items: center;
        }

        /* ============================================================
           Buttons
           ============================================================ */
        .rip-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0 16px;
            height: 36px;
            border: none;
            border-radius: var(--rip-radius-md);
            font-size: var(--rip-font-size-base);
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: background var(--rip-transition), color var(--rip-transition), box-shadow var(--rip-transition);
            white-space: nowrap;
            line-height: 1;
        }
        .rip-button--primary { background: var(--rip-primary); color: #fff; }
        .rip-button--primary:hover { background: var(--rip-primary-hover); }
        .rip-button--secondary { background: var(--rip-gray-100); color: var(--rip-gray-600); }
        .rip-button--secondary:hover { background: var(--rip-gray-200); }
        .rip-button--ghost { background: none; color: var(--rip-gray-500); }
        .rip-button--ghost:hover { color: var(--rip-gray-700); background: var(--rip-gray-100); }
        .rip-button--danger { background: none; border: none; color: var(--rip-danger); cursor: pointer; font-size: var(--rip-font-size-base); text-decoration: underline; }
        .rip-button--danger:hover { color: #DC2626; }
        .rip-button--success { background: var(--rip-success); color: #fff; }
        .rip-button--success:hover { background: #059669; }
        .rip-button--sm { height: 30px; padding: 0 12px; font-size: var(--rip-font-size-sm); }
        .rip-button--lg { height: 40px; padding: 0 24px; font-size: var(--rip-font-size-md); }

        /* ============================================================
           Forms
           ============================================================ */
        .rip-form-group { margin-bottom: var(--rip-space-lg); }
        .rip-label { display: block; font-size: var(--rip-font-size-xs); font-weight: 600; color: var(--rip-gray-500); margin-bottom: 3px; text-transform: uppercase; letter-spacing: 0.3px; }
        .rip-input, .rip-select, .rip-textarea {
            width: 100%;
            padding: 7px 12px;
            height: 36px;
            border: 1px solid var(--rip-gray-300);
            border-radius: var(--rip-radius-md);
            font-size: var(--rip-font-size-base);
            font-family: var(--rip-font-family);
            background: var(--rip-bg-card);
            transition: border-color var(--rip-transition), box-shadow var(--rip-transition);
        }
        .rip-input:focus, .rip-select:focus, .rip-textarea:focus {
            outline: none;
            border-color: var(--rip-primary);
            box-shadow: 0 0 0 3px rgba(79,70,229,0.12);
        }
        .rip-textarea { resize: vertical; height: auto; }
        .rip-help-text { font-size: var(--rip-font-size-xs); color: var(--rip-gray-400); margin-top: var(--rip-space-xs); }

        /* Filter bar layout helper */
        .rip-filter-bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end; }
        .rip-filter-bar .rip-input,
        .rip-filter-bar .rip-select { width: auto; }
        .rip-filter-bar .rip-button { height: 36px; }

        /* ============================================================
           Stat Cards
           ============================================================ */
        .rip-stat-card {
            background: var(--rip-bg-card);
            border-radius: var(--rip-radius-lg);
            box-shadow: var(--rip-shadow-md);
            padding: 16px var(--rip-space-xl);
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .rip-stat-card__icon {
            width: 40px; height: 40px;
            border-radius: var(--rip-radius-lg);
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }
        .rip-stat-card__icon svg { width: 20px; height: 20px; }
        .rip-stat-card__icon--success { background: var(--rip-success-light); color: var(--rip-success); }
        .rip-stat-card__icon--danger { background: var(--rip-danger-light); color: var(--rip-danger); }
        .rip-stat-card__icon--warning { background: var(--rip-warning-light); color: var(--rip-warning); }
        .rip-stat-card__icon--info { background: var(--rip-info-light); color: var(--rip-info); }
        .rip-stat-card__content { flex: 1; min-width: 0; }
        .rip-stat-card__label {
            font-size: 10px;
            color: var(--rip-gray-500);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .rip-stat-card__value { font-size: 26px; font-weight: 700; margin-top: 1px; line-height: 1.2; }

        /* ============================================================
           Dashboard Grids
           ============================================================ */
        .rip-grid { display: grid; gap: var(--rip-space-xl); margin-bottom: var(--rip-space-xl); }
        .rip-grid > .rip-card { margin-bottom: 0; }
        .rip-grid--kpi { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; }
        .rip-grid--2 { grid-template-columns: 1fr 1fr; }
        .rip-grid--3 { grid-template-columns: repeat(3, 1fr); }
        .rip-grid--main { grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr); }
        @media (max-width: 1100px) {
            .rip-grid--2, .rip-grid--3, .rip-grid--main { grid-template-columns: 1fr; }
        }

        /* ============================================================
           Stat Card Extensions (trend chip, hint, clickable)
           ============================================================ */
        .rip-stat-card__trend {
            display: inline-flex; align-items: center; gap: 3px;
            font-size: var(--rip-font-size-xs); font-weight: 700;
            padding: 1px 7px; border-radius: var(--rip-radius-full);
            vertical-align: 3px; margin-left: 6px;
        }
        .rip-stat-card__trend--up { background: var(--rip-danger-light); color: var(--rip-danger-text); }
        .rip-stat-card__trend--down { background: var(--rip-success-light); color: var(--rip-success-text); }
        .rip-stat-card__trend--flat { background: var(--rip-gray-100); color: var(--rip-gray-500); }
        .rip-stat-card__hint { font-size: var(--rip-font-size-xs); color: var(--rip-gray-400); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        a.rip-stat-card { text-decoration: none; color: inherit; transition: box-shadow var(--rip-transition); }
        a.rip-stat-card:hover { box-shadow: var(--rip-shadow-lg); }

        /* ============================================================
           Segmented Control
           ============================================================ */
        .rip-seg { display: inline-flex; gap: 4px; background: var(--rip-gray-100); padding: 3px; border-radius: var(--rip-radius-full); }
        .rip-seg__btn {
            border: none; cursor: pointer; padding: 4px 12px; font: inherit;
            font-size: var(--rip-font-size-sm); font-weight: 500;
            border-radius: var(--rip-radius-full); background: transparent;
            color: var(--rip-gray-500); transition: background var(--rip-transition), color var(--rip-transition);
        }
        .rip-seg__btn:hover { color: var(--rip-gray-700); }
        .rip-seg__btn[aria-selected="true"] { background: var(--rip-bg-card); color: var(--rip-primary); box-shadow: var(--rip-shadow-sm); }

        /* ============================================================
           Activity Chart
           ============================================================ */
        .rip-chart__meta { font-size: var(--rip-font-size-xs); color: var(--rip-gray-400); margin-bottom: 4px; }
        .rip-chart__bars { display: flex; align-items: flex-end; gap: 3px; height: 140px; padding-top: 8px; border-bottom: 1px solid var(--rip-gray-100); }
        .rip-chart__col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; min-width: 0; }
        .rip-chart__bar {
            width: 100%; min-height: 2px; max-height: 100%;
            background: linear-gradient(180deg, var(--rip-info) 0%, var(--rip-primary) 100%);
            border-radius: var(--rip-radius-sm) var(--rip-radius-sm) 0 0;
            transition: opacity var(--rip-transition);
        }
        .rip-chart__bar--zero { background: var(--rip-gray-200); }
        .rip-chart__col:hover .rip-chart__bar { opacity: 0.7; }
        .rip-chart__labels { display: flex; gap: 3px; margin-top: 4px; }
        .rip-chart__label { flex: 1; text-align: center; font-size: var(--rip-font-size-xs); color: var(--rip-gray-400); min-width: 0; }

        /* ============================================================
           Bar List (horizontal ranking bars)
           ============================================================ */
        .rip-bar-list { display: flex; flex-direction: column; gap: 8px; }
        .rip-bar-list__row { display: flex; align-items: center; gap: 10px; font-size: var(--rip-font-size-base); min-width: 0; }
        .rip-bar-list__label { width: 100px; flex-shrink: 0; color: var(--rip-gray-600); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .rip-bar-list__label--wide { width: 170px; font-family: var(--rip-font-mono); font-size: var(--rip-font-size-sm); }
        .rip-bar-list__track { flex: 1; height: 16px; background: var(--rip-gray-100); border-radius: var(--rip-radius-sm); overflow: hidden; }
        .rip-bar-list__fill { height: 100%; background: var(--rip-primary); border-radius: var(--rip-radius-sm); min-width: 2px; }
        .rip-bar-list__value { min-width: 48px; text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }

        /* ============================================================
           Severity Meter & Legend
           ============================================================ */
        .rip-meter { display: flex; height: 14px; border-radius: var(--rip-radius-full); overflow: hidden; background: var(--rip-gray-100); }
        .rip-meter__seg { min-width: 0; }
        .rip-meter__seg--critical { background: #DC2626; }
        .rip-meter__seg--high { background: #F97316; }
        .rip-meter__seg--medium { background: #FACC15; }
        .rip-meter__seg--low { background: #22C55E; }
        .rip-legend { display: flex; flex-direction: column; gap: 8px; margin-top: 14px; }
        .rip-legend__row { display: flex; align-items: center; gap: 8px; font-size: var(--rip-font-size-base); }
        .rip-legend__dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
        .rip-legend__dot--critical { background: #DC2626; }
        .rip-legend__dot--high { background: #F97316; }
        .rip-legend__dot--medium { background: #FACC15; }
        .rip-legend__dot--low { background: #22C55E; }
        .rip-legend__label { flex: 1; color: var(--rip-gray-600); }
        .rip-legend__value { font-weight: 600; font-variant-numeric: tabular-nums; }
        .rip-legend__pct { color: var(--rip-gray-400); font-size: var(--rip-font-size-xs); min-width: 38px; text-align: right; }

        /* ============================================================
           Threat Intel Card (dark)
           ============================================================ */
        .rip-intel-card {
            background: var(--rip-gradient-dark);
            color: var(--rip-gray-300);
            border-radius: var(--rip-radius-lg);
            box-shadow: var(--rip-shadow-md);
            padding: var(--rip-space-xl);
            margin-bottom: var(--rip-space-xl);
        }
        .rip-intel-card__header {
            display: flex; align-items: center; justify-content: space-between;
            gap: 12px; flex-wrap: wrap;
            margin-bottom: 14px; padding-bottom: 12px;
            border-bottom: 1px solid var(--rip-sidebar-border);
        }
        .rip-intel-card__title { font-size: var(--rip-font-size-md); font-weight: 600; color: #FFFFFF; display: inline-flex; align-items: center; gap: 8px; }
        .rip-intel-card__title svg { width: 16px; height: 16px; color: var(--rip-sidebar-active-text); }
        .rip-intel-card__chips { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        .rip-intel-card__grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--rip-space-2xl); }
        @media (max-width: 1100px) { .rip-intel-card__grid { grid-template-columns: 1fr; } }
        .rip-intel-card__subtitle {
            font-size: var(--rip-font-size-xs); font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.5px; color: var(--rip-gray-500); margin-bottom: 6px;
        }
        .rip-link--light { color: var(--rip-sidebar-active-text); text-decoration: none; font-size: var(--rip-font-size-sm); }
        .rip-link--light:hover { color: #FFFFFF; }

        /* Chips (dark-card counters) */
        .rip-chip {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 2px 10px; border-radius: var(--rip-radius-full);
            font-size: var(--rip-font-size-sm);
            background: rgba(255,255,255,0.08); color: var(--rip-gray-300);
        }
        .rip-chip strong { color: #FFFFFF; font-variant-numeric: tabular-nums; }
        .rip-chip--danger { background: rgba(239,68,68,0.22); color: #FCA5A5; }
        .rip-chip--danger strong { color: #FECACA; }

        /* Feed (event list inside dark card) */
        .rip-feed { list-style: none; display: flex; flex-direction: column; }
        .rip-feed__item {
            display: flex; gap: 10px; align-items: baseline;
            padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.06);
            font-size: var(--rip-font-size-base); min-width: 0;
        }
        .rip-feed__item:last-child { border-bottom: none; }
        .rip-feed__time { color: var(--rip-gray-500); font-size: var(--rip-font-size-xs); white-space: nowrap; flex-shrink: 0; font-variant-numeric: tabular-nums; }
        .rip-feed__text { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .rip-feed__mono { font-family: var(--rip-font-mono); font-size: var(--rip-font-size-sm); color: #E5E7EB; }
        .rip-feed__empty { padding: 14px 0; color: var(--rip-gray-500); font-size: var(--rip-font-size-base); }

        /* ============================================================
           Status Pill (health indicator)
           ============================================================ */
        .rip-status-pill {
            display: inline-flex; align-items: center; gap: 6px;
            font-size: var(--rip-font-size-sm); font-weight: 400;
            padding: 2px 10px; border-radius: var(--rip-radius-full);
            border: 1px solid transparent;
        }
        .rip-status-pill__dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
        .rip-status-pill--healthy { background: var(--rip-success-light); color: var(--rip-success-text); border-color: var(--rip-success-border); }
        .rip-status-pill--healthy .rip-status-pill__dot { background: var(--rip-success); }
        .rip-status-pill--warning { background: var(--rip-warning-light); color: var(--rip-warning-text); border-color: var(--rip-warning-border); }
        .rip-status-pill--warning .rip-status-pill__dot { background: var(--rip-warning); }
        .rip-status-pill--critical { background: var(--rip-danger-light); color: var(--rip-danger-text); border-color: var(--rip-danger-border); }
        .rip-status-pill--critical .rip-status-pill__dot { background: var(--rip-danger); }
        .rip-status-pill--unknown { background: var(--rip-gray-100); color: var(--rip-gray-500); border-color: var(--rip-gray-300); }
        .rip-status-pill--unknown .rip-status-pill__dot { background: var(--rip-gray-400); }

        /* ============================================================
           Key/Value Grid (system info)
           ============================================================ */
        .rip-kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; }
        .rip-kv__key {
            font-size: var(--rip-font-size-xs); font-weight: 600; color: var(--rip-gray-500);
            text-transform: uppercase; letter-spacing: 0.3px;
        }
        .rip-kv__val { margin-top: 2px; font-size: var(--rip-font-size-base); font-weight: 500; color: var(--rip-gray-800); }

        /* Card header helpers */
        .rip-card__header--flex { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
        .rip-card__header-meta { font-size: var(--rip-font-size-sm); font-weight: 400; color: var(--rip-gray-500); }

        /* ============================================================
           Empty State
           ============================================================ */
        .rip-empty-state { text-align: center; padding: 40px 20px; }
        .rip-empty-state__icon { font-size: 48px; margin-bottom: 12px; color: var(--rip-gray-300); }
        .rip-empty-state__title { font-size: 15px; color: var(--rip-gray-500); margin-bottom: 8px; }
        .rip-empty-state__text { font-size: var(--rip-font-size-base); color: var(--rip-gray-400); margin-bottom: 16px; }
        .rip-empty-state__actions { margin-top: 12px; }

        /* ============================================================
           Trust Badges
           ============================================================ */
        .rip-trust-badges {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: var(--rip-space-lg);
            padding: var(--rip-space-lg) 0;
            margin-top: var(--rip-space-xl);
            border-top: 1px solid var(--rip-gray-200);
            flex-wrap: wrap;
        }
        .rip-trust-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: var(--rip-font-size-xs);
            color: var(--rip-gray-400);
            font-weight: 500;
        }
        .rip-trust-badge svg { width: 14px; height: 14px; }

        /* ============================================================
           Toggle
           ============================================================ */
        .rip-toggle { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; }
        .rip-toggle__input { display: none; }
        .rip-toggle__slider {
            width: 36px; height: 20px; background: var(--rip-gray-300); border-radius: 10px;
            position: relative; transition: background var(--rip-transition);
        }
        .rip-toggle__slider::after {
            content: ''; position: absolute; width: 16px; height: 16px;
            background: #fff; border-radius: 50%; top: 2px; left: 2px;
            transition: transform var(--rip-transition);
        }
        .rip-toggle__input:checked + .rip-toggle__slider { background: var(--rip-primary); }
        .rip-toggle__input:checked + .rip-toggle__slider::after { transform: translateX(16px); }
        .rip-toggle__label { font-size: var(--rip-font-size-base); color: var(--rip-gray-600); }

        /* ============================================================
           Mode Badge
           ============================================================ */
        .rip-mode-badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 2px 10px; border-radius: var(--rip-radius-full);
            font-size: var(--rip-font-size-sm); font-weight: 500;
        }
        .rip-mode-badge--local { background: var(--rip-gray-100); color: var(--rip-gray-600); }
        .rip-mode-badge--community { background: var(--rip-primary-light); color: var(--rip-primary); }

        /* ============================================================
           Nav Tabs
           ============================================================ */
        .rip-nav-tabs {
            display: flex; gap: 0; border-bottom: 2px solid var(--rip-gray-200);
            margin-bottom: var(--rip-space-xl);
        }
        .rip-nav-tabs__tab {
            padding: 10px 18px; font-size: var(--rip-font-size-base); color: var(--rip-gray-500);
            text-decoration: none; border-bottom: 2px solid transparent;
            margin-bottom: -2px; transition: color var(--rip-transition), border-color var(--rip-transition);
        }
        .rip-nav-tabs__tab:hover { color: var(--rip-gray-700); }
        .rip-nav-tabs__tab--active { color: var(--rip-primary); border-bottom-color: var(--rip-primary); font-weight: 600; }

        /* ============================================================
           Pagination
           ============================================================ */
        .rip-pagination { display: flex; gap: 4px; margin-top: var(--rip-space-lg); justify-content: center; }
        .rip-pagination a, .rip-pagination span {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 32px; height: 32px; padding: 0 8px;
            border-radius: var(--rip-radius-md);
            text-decoration: none; font-size: var(--rip-font-size-base);
            color: var(--rip-gray-600); background: var(--rip-bg-card); border: var(--rip-border);
        }
        .rip-pagination a:hover { background: var(--rip-bg); }
        .rip-pagination .current { background: var(--rip-primary); color: #fff; border-color: var(--rip-primary); }

        /* ============================================================
           IP External Link
           ============================================================ */
        .rip-ip-external { color: var(--rip-gray-400); text-decoration: none; margin-left: 3px; font-size: var(--rip-font-size-xs); }
        .rip-ip-external:hover { color: var(--rip-primary); }

        /* ============================================================
           Utility: Links
           ============================================================ */
        .rip-link { color: var(--rip-primary); text-decoration: none; }
        .rip-link:hover { color: var(--rip-primary-hover); }
        .rip-link--muted { color: var(--rip-gray-500); }
        .rip-link--muted:hover { color: var(--rip-gray-700); }

        /* ============================================================
           Responsive
           ============================================================ */
        @media (max-width: 768px) {
            .rip-sidebar { display: none; }
            .rip-main { margin-left: 0; }
        }
    </style>
</head>
<body>
    <nav class="rip-sidebar">
        <div class="rip-sidebar__brand">
            <svg width="26" height="26" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M16 2L4 8v8c0 7.73 5.12 14.96 12 16.8C22.88 30.96 28 23.73 28 16V8L16 2z" fill="#4F46E5" opacity="0.15"/>
                <path d="M16 2L4 8v8c0 7.73 5.12 14.96 12 16.8C22.88 30.96 28 23.73 28 16V8L16 2z" stroke="#A5B4FC" stroke-width="1.5" fill="none"/>
                <path d="M12 16l3 3 5-6" stroke="#A5B4FC" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
            </svg>
            ReportedIP Honeypot
        </div>
        <div class="rip-sidebar__nav">
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/" class="<?= ($active_tab ?? '') === '' || ($active_tab ?? '') === 'dashboard' ? 'active' : '' ?>">
                <i class="icon">&#9632;</i> Dashboard
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs" class="<?= ($active_tab ?? '') === 'logs' ? 'active' : '' ?>">
                <i class="icon">&#9776;</i> Logs
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/whitelist" class="<?= ($active_tab ?? '') === 'whitelist' ? 'active' : '' ?>">
                <i class="icon">&#10003;</i> Whitelist
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content" class="<?= ($active_tab ?? '') === 'content' ? 'active' : '' ?>">
                <i class="icon">&#9998;</i> Content
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/visitors" class="<?= ($active_tab ?? '') === 'visitors' ? 'active' : '' ?>">
                <i class="icon">&#9881;</i> Visitors
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/intel" class="<?= ($active_tab ?? '') === 'intel' ? 'active' : '' ?>">
                <i class="icon">&#9873;</i> Threat Intel
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks" class="<?= ($active_tab ?? '') === 'webhooks' ? 'active' : '' ?>">
                <i class="icon">&#8674;</i> Webhooks
            </a>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/updates" class="<?= ($active_tab ?? '') === 'updates' ? 'active' : '' ?>">
                <i class="icon">&#8635;</i> Updates
                <?php
                    $__updateAvail = false;
                    $__updateStatusPath = dirname(__DIR__, 2) . '/data/update_status.json';
                    if (file_exists($__updateStatusPath)) {
                        $__uData = @json_decode((string) file_get_contents($__updateStatusPath), true);
                        if (is_array($__uData) && ($__uData['update_available'] ?? false)) {
                            $__updateAvail = true;
                        }
                    }
                ?>
                <?php if ($__updateAvail): ?>
                    <span style="margin-left:auto; background:var(--rip-warning); color:#fff; font-size:9px; padding:1px 6px; border-radius:var(--rip-radius-full); font-weight:700;">1</span>
                <?php endif; ?>
            </a>
        </div>
        <div class="rip-sidebar__footer">
            <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logout" style="margin:0;">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
                <button type="submit" class="rip-sidebar__logout-btn">Logout</button>
            </form>
        </div>
    </nav>

    <div class="rip-main">
        <header class="rip-header">
            <h1><?= htmlspecialchars($page_title ?? 'Dashboard', ENT_QUOTES, 'UTF-8') ?></h1>
            <div class="rip-header__meta"><?= date('Y-m-d H:i:s') ?></div>
        </header>
        <div class="rip-content">
            <?php if (!empty($message)): ?>
                <div class="rip-alert rip-alert--<?= ($message_type ?? 'success') === 'error' ? 'error' : 'success' ?>">
                    <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>
            <?= $content ?? '' ?>

            <div class="rip-trust-badges">
                <span class="rip-trust-badge">
                    <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg>
                    Security Focused
                </span>
                <span class="rip-trust-badge">
                    <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm3.5 7.5h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1z"/></svg>
                    GDPR Compliant
                </span>
                <span class="rip-trust-badge">
                    <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1L1 5v6l7 4 7-4V5L8 1zm0 1.2L13.5 5.5 8 8.8 2.5 5.5 8 2.2zM2 6.3l5.5 3.1v4.3L2 10.6V6.3zm7 7.4V9.4L14 6.3v4.3L9 13.7z"/></svg>
                    Made in Germany
                </span>
            </div>
        </div>
    </div>
</body>
</html>
