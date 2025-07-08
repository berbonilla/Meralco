# Malware Scanner Frontend Pages

This directory contains the modern, minimalist frontend for the Malware Scanner API.

## Pages

- **dashboard.html** - Main landing page with welcome message
- **upload.html** - File upload interface for ZIP, TXT, and CSV files
- **hash_input.html** - Manual hash input interface
- **spreadsheet.html** - Spreadsheet integration interface
- **results.html** - Scan results and analytics dashboard
- **log.html** - Activity log viewer
- **index.html** - Redirects to dashboard

## Features

- **Modern Design**: Minimalist, monochrome interface with smooth animations
- **Dark/Light Mode**: Toggle between themes with persistent settings
- **Responsive**: Works on desktop, tablet, and mobile devices
- **Navigation**: Sticky navigation bar with active page highlighting
- **Professional**: Clean typography, proper spacing, and modern UI patterns

## Usage

1. Start the API server: `python scanner_api.py`
2. Open `pages/index.html` in your browser
3. Navigate between pages using the top navigation bar
4. Toggle theme using the "Toggle Theme" button

## Files

- **style.css** - Shared styles for all pages
- **script.js** - Shared JavaScript functionality
- **index.html** - Entry point (redirects to dashboard)

## Design Principles

- No icons - text-only interface
- Monochrome color scheme
- Generous whitespace
- Smooth transitions
- Professional typography
- Mobile-first responsive design 