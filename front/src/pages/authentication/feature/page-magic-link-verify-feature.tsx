import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useVerifyMagicLink } from '@/api/trident.api'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { MagicCard } from '@/components/magicui/magic-card'
import { AuthenticationStatus } from '@/api/api.interface'

export default function PageMagicLinkVerifyFeature() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [isVerifying, setIsVerifying] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const { mutate: verifyMagicLink } = useVerifyMagicLink()

  useEffect(() => {
    const verifyLink = async () => {
      const realmName = searchParams.get('realm_name')
      const tokenId = searchParams.get('token_id')
      const magicToken = searchParams.get('magic_token')
      const clientId = searchParams.get('client_id')

      if (!realmName || !tokenId || !magicToken || !clientId) {
        setError('Invalid magic link. Missing required parameters.')
        setIsVerifying(false)
        return
      }

      try {
        verifyMagicLink(
          {
            path: {
              realm_name: realmName,
            },
            query: {
              token_id: tokenId,
              magic_token: magicToken,
              client_id: clientId,
            },
          },
          {
            onSuccess: async (response) => {
              const data = await response.json()
              if (data.status === AuthenticationStatus.Success && data.url) {
                window.location.href = data.url
              } else if (data.url) {
                window.location.href = data.url
              } else {
                setError('Unexpected response from server')
                setIsVerifying(false)
              }
            },
            onError: (error: Error) => {
              const message = error?.message || 'Failed to verify magic link'
              setError(message)
              toast.error(message)
              setIsVerifying(false)
            },
          }
        )
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'An error occurred while verifying the link'
        setError(message)
        setIsVerifying(false)
      }
    }

    verifyLink()
  }, [searchParams, verifyMagicLink])

  if (isVerifying) {
    return (
      <div className='flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10'>
        <div className='w-full max-w-sm md:max-w-3xl'>
          <Card className='overflow-hidden p-0'>
            <MagicCard className='p-0' gradientColor='#D9D9D955'>
              <CardContent className='p-6 md:p-8'>
                <div className='flex flex-col gap-4 items-center justify-center'>
                  <div className='animate-spin rounded-full h-12 w-12 border-b-2 border-primary'></div>
                  <h2 className='text-lg font-semibold'>Verifying your magic link...</h2>
                  <p className='text-sm text-muted-foreground'>
                    Please wait while we verify your link
                  </p>
                </div>
              </CardContent>
            </MagicCard>
          </Card>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className='flex min-h-svh flex-col items-center justify-center bg-muted p-6 md:p-10'>
        <div className='w-full max-w-sm md:max-w-3xl'>
          <Card className='overflow-hidden p-0'>
            <MagicCard className='p-0' gradientColor='#D9D9D955'>
              <CardContent className='p-6 md:p-8'>
                <div className='flex flex-col gap-4'>
                  <div className='rounded-lg bg-destructive/10 p-4 border border-destructive/50'>
                    <h2 className='text-lg font-semibold text-destructive'>
                      Link Verification Failed
                    </h2>
                    <p className='text-sm text-destructive/80 mt-2'>{error}</p>
                  </div>
                  <p className='text-sm text-muted-foreground'>
                    The magic link may have expired or is invalid.
                  </p>
                  <Button
                    onClick={() => navigate('/realms/master/authentication/login')}
                    className='w-full'
                  >
                    Back to Login
                  </Button>
                </div>
              </CardContent>
            </MagicCard>
          </Card>
        </div>
      </div>
    )
  }

  return null
}
