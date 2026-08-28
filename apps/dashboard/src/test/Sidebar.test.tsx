import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';

import { Sidebar } from '../components/Sidebar';

describe('Sidebar Component', () => {
  it('renders Sentinel navigation links properly', () => {
    render(
      <BrowserRouter>
        <Sidebar pendingApprovalsCount={3} />
      </BrowserRouter>
    );

    expect(screen.getByText('SENTINEL')).toBeInTheDocument();
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Tasks')).toBeInTheDocument();
    expect(screen.getByText('Findings')).toBeInTheDocument();
    expect(screen.getByText('Approvals')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });
});
