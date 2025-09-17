import './index.css';

import { render } from 'preact'

import { App } from './app.tsx'

async function main() {
  render(<App />, document.getElementById('pingoo-captcha')!)
}

main();
